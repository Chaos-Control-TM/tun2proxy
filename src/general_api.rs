use crate::Args;
use std::os::raw::{c_char, c_int, c_ushort};

/// # Safety
/// Run the tun2proxy component with command line arguments
/// Parameters:
/// - cli_args: The command line arguments,
///   e.g. `tun2proxy-bin --setup --proxy socks5://127.0.0.1:1080 --bypass 98.76.54.0/24 --dns over-tcp --verbosity trace`
/// - tun_mtu: The MTU of the TUN device, e.g. 1500
/// - packet_information: Whether exists packet information in packet from TUN device
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tun2proxy_run_with_cli_args(cli_args: *const c_char, tun_mtu: c_ushort, packet_information: bool) -> c_int {
    let Ok(cli_args) = unsafe { std::ffi::CStr::from_ptr(cli_args) }.to_str() else {
        log::error!("Failed to convert CLI arguments to string");
        return -5;
    };
    let Some(args) = shlex::split(cli_args) else {
        log::error!("Failed to split CLI arguments");
        return -6;
    };
    let Ok(args) = <Args as ::clap::Parser>::try_parse_from(args) else {
        log::error!("Failed to parse CLI arguments");
        return -7;
    };
    general_run_for_api(args, tun_mtu, packet_information)
}

static TUN_QUIT: std::sync::Mutex<Option<tokio_util::sync::CancellationToken>> = std::sync::Mutex::new(None);

struct RunTokenGuard;

impl Drop for RunTokenGuard {
    fn drop(&mut self) {
        match TUN_QUIT.lock() {
            Ok(mut lock) => {
                lock.take();
            }
            Err(err) => log::error!("failed to clear tun2proxy quit token: {err}"),
        }
    }
}

pub(crate) fn tun2proxy_stop_internal() -> c_int {
    if let Ok(lock) = TUN_QUIT.lock()
        && let Some(shutdown_token) = lock.as_ref()
    {
        shutdown_token.cancel();
        return 0;
    }
    -1
}

pub fn general_run_for_api(args: Args, tun_mtu: u16, packet_information: bool) -> c_int {
    log::set_max_level(args.verbosity);
    if let Err(err) = log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()) {
        log::debug!("set logger error: {err}");
    }

    let shutdown_token = tokio_util::sync::CancellationToken::new();
    if let Ok(mut lock) = TUN_QUIT.lock() {
        if lock.is_some() {
            log::error!("tun2proxy already started");
            return -1;
        }
        *lock = Some(shutdown_token.clone());
    } else {
        log::error!("failed to lock tun2proxy quit token");
        return -2;
    }
    let _run_token_guard = RunTokenGuard;

    let Ok(rt) = tokio::runtime::Builder::new_multi_thread().enable_all().build() else {
        log::error!("failed to create tokio runtime with");
        return -3;
    };
    let args_clone = args.clone();
    log::info!("tun2proxy (DLL): entering runtime.block_on...");
    let res = rt.block_on(async move { general_run_async(args_clone, tun_mtu, packet_information, shutdown_token).await });
    log::info!("tun2proxy (DLL): runtime.block_on returned");

    // This is a DLL/API entrypoint: never terminate the host process.
    // Use a bounded runtime shutdown to avoid potentially blocking forever on Drop.
    log::info!(
        "tun2proxy (DLL): shutting down tokio runtime (timeout: {:?})...",
        crate::FORCE_EXIT_TIMEOUT
    );
    rt.shutdown_timeout(crate::FORCE_EXIT_TIMEOUT);
    log::info!("tun2proxy (DLL): tokio runtime shutdown complete");

    match res {
        Ok(sessions) => {
            log::debug!("tun2proxy exited normally, current session count: {sessions}");
            0
        }
        Err(e) => {
            log::error!("failed to run tun2proxy with error: {e:?}");
            -4
        }
    }
}

/// Run the tun2proxy component with some arguments.
pub async fn general_run_async(
    args: Args,
    tun_mtu: u16,
    _packet_information: bool,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> std::io::Result<usize> {
    let mut args = args;
    let _proxy_addr = if let Some(addr) = args.proxy.addr.as_ref()
        && let Some(addr) = addr.resolve_using_tokio().await?.next()
    {
        args.proxy.addr = Some(addr.into());
        Some(addr)
    } else {
        None
    };

    let mut tun_config = tun::Configuration::default();

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    {
        use tproxy_config::{TUN_GATEWAY, TUN_IPV4, TUN_NETMASK};
        tun_config.address(TUN_IPV4).netmask(TUN_NETMASK).mtu(tun_mtu).up();
        tun_config.destination(TUN_GATEWAY);
    }

    #[cfg(unix)]
    if let Some(fd) = args.tun_fd {
        tun_config.raw_fd(fd);
        if let Some(v) = args.close_fd_on_drop {
            tun_config.close_fd_on_drop(v);
        };
    } else if let Some(ref tun) = args.tun {
        tun_config.tun_name(tun);
    }
    #[cfg(windows)]
    if let Some(ref tun) = args.tun {
        tun_config.tun_name(tun);
    }

    #[cfg(target_os = "linux")]
    tun_config.platform_config(|cfg| {
        #[allow(deprecated)]
        cfg.packet_information(true);
        cfg.ensure_root_privileges(args.setup);
    });

    #[cfg(target_os = "windows")]
    tun_config.platform_config(|cfg| {
        cfg.device_guid(12324323423423434234_u128);
    });

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    tun_config.platform_config(|cfg| {
        cfg.packet_information(_packet_information);
    });

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[allow(unused_variables)]
    let mut tproxy_args = tproxy_config::TproxyArgs::new()
        .tun_dns(args.dns_addr)
        .proxy_addr(_proxy_addr.unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0))))
        .bypass_ips(&args.bypass)
        .ipv6_default_route(args.ipv6_enabled);

    let device = tun::create_as_async(&tun_config)?;

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if let Ok(tun_name) = tun::AbstractDevice::tun_name(&*device) {
        // Above line is equivalent to: `use tun::AbstractDevice; if let Ok(tun_name) = device.tun_name() {`
        tproxy_args = tproxy_args.tun_name(&tun_name);
    }

    // TproxyState implements the Drop trait to restore network configuration,
    // so we need to assign it to a variable, even if it is not used.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    let mut restore: Option<tproxy_config::TproxyState> = None;

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if args.setup {
        restore = Some(tproxy_config::tproxy_setup(&tproxy_args).await?);
    }

    #[cfg(all(target_os = "linux", feature = "unshare"))]
    {
        let mut admin_command_args = args.admin_command.iter();
        if let Some(command) = admin_command_args.next() {
            let child = tokio::process::Command::new(command)
                .args(admin_command_args)
                .kill_on_drop(true)
                .spawn();

            match child {
                Err(err) => {
                    log::warn!("Failed to start admin process: {err}");
                }
                Ok(mut child) => {
                    tokio::spawn(async move {
                        if let Err(err) = child.wait().await {
                            log::warn!("Admin process terminated: {err}");
                        }
                    });
                }
            };
        }
    }

    let join_handle = tokio::spawn(crate::run(device, tun_mtu, args.clone(), shutdown_token.clone()));

    match join_handle.await? {
        Ok(sessions) => {
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            tproxy_config::tproxy_remove(restore).await?;

            let max_sessions = args.max_sessions;
            if args.exit_on_fatal_error && sessions >= max_sessions {
                let info = format!("Forced exit due to max sessions reached ({sessions}/{max_sessions})");
                return Err(std::io::Error::other(info));
            }
            Ok(sessions)
        }
        Err(err) => Err(std::io::Error::from(err)),
    }
}

/// # Safety
///
/// Shutdown the tun2proxy component.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tun2proxy_stop() -> c_int {
    tun2proxy_stop_internal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_token_guard_clears_global_state_after_stop() {
        let token = tokio_util::sync::CancellationToken::new();
        {
            let mut lock = TUN_QUIT.lock().unwrap();
            assert!(lock.is_none());
            *lock = Some(token.clone());
        }

        let guard = RunTokenGuard;
        assert_eq!(tun2proxy_stop_internal(), 0);
        assert!(token.is_cancelled());
        assert!(TUN_QUIT.lock().unwrap().is_some());

        drop(guard);
        assert!(TUN_QUIT.lock().unwrap().is_none());
    }
}
