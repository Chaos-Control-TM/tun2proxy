//! Routes owned by one TUN lifetime. Never remove or recreate uplink routes.
use std::io;
use windows_sys::Win32::{
    NetworkManagement::IpHelper::{CreateIpForwardEntry2, DeleteIpForwardEntry2,
        InitializeIpForwardEntry, MIB_IPFORWARD_ROW2},
    Networking::WinSock::AF_INET,
};

pub struct Routes(Vec<MIB_IPFORWARD_ROW2>);
impl Routes {
    pub fn install(luid: u64, index: u32) -> io::Result<Self> {
        let mut routes = Self(Vec::new());
        for first in [0, 128] {
            let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
            unsafe {
                InitializeIpForwardEntry(&mut row);
                row.InterfaceLuid.Value = luid;
                row.InterfaceIndex = index;
                row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
                row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([first, 0, 0, 0]);
                row.DestinationPrefix.PrefixLength = 1;
                row.NextHop.Ipv4.sin_family = AF_INET;
                row.NextHop.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([10, 0, 0, 1]);
                row.Metric = 6;
                row.Protocol = 3; // MIB_IPPROTO_NETMGMT
                let code = CreateIpForwardEntry2(&row);
                if code != 0 { return Err(io::Error::from_raw_os_error(code as i32)); }
            }
            routes.0.push(row);
        }
        Ok(routes)
    }
}
impl Drop for Routes {
    fn drop(&mut self) {
        for row in &self.0 {
            let code = unsafe { DeleteIpForwardEntry2(row) };
            if code != 0 && code != 1168 { log::error!("owned route cleanup failed: {code}"); }
        }
    }
}
