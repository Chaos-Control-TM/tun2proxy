use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{
        Name, RData, Record,
        rdata::{A, AAAA},
    },
};
use std::io::{Error, ErrorKind::InvalidData, ErrorKind::UnexpectedEof};
use std::{net::IpAddr, str::FromStr};

pub fn build_dns_response(mut request: Message, domain: &str, ip: IpAddr, ttl: u32) -> std::io::Result<Message> {
    let name = Name::from_str(domain).map_err(|e| Error::new(InvalidData, e))?;
    let record = match ip {
        IpAddr::V4(ip) => Record::from_rdata(name.clone(), ttl, RData::A(A(ip))),
        IpAddr::V6(ip) => Record::from_rdata(name, ttl, RData::AAAA(AAAA(ip))),
    };

    // We must indicate that this message is a response. Otherwise, implementations may not
    // recognize it.
    request.metadata.message_type = MessageType::Response;

    request.add_answer(record);
    Ok(request)
}

pub fn remove_ipv6_entries(message: &mut Message) {
    message.answers.retain(|answer| !matches!(&answer.data, RData::AAAA(_)));
}

pub fn extract_ipaddr_from_dns_message(message: &Message) -> std::io::Result<IpAddr> {
    if message.metadata.response_code != ResponseCode::NoError {
        return Err(Error::new(InvalidData, format!("{:?}", message.metadata.response_code)));
    }
    let mut cname = None;
    for answer in &message.answers {
        match &answer.data {
            RData::A(addr) => {
                return Ok(IpAddr::V4((*addr).into()));
            }
            RData::AAAA(addr) => {
                return Ok(IpAddr::V6((*addr).into()));
            }
            RData::CNAME(name) => {
                cname = Some(name.to_utf8());
            }
            _ => {}
        }
    }
    if let Some(cname) = cname {
        return Err(Error::new(InvalidData, cname));
    }
    Err(Error::new(InvalidData, format!("{:?}", message.answers)))
}

pub fn extract_domain_from_dns_message(message: &Message) -> std::io::Result<String> {
    use std::io::{Error, ErrorKind::InvalidData};
    let query = message.queries.first().ok_or(Error::new(InvalidData, "DnsRequest no query body"))?;
    let name = query.name().to_ascii();
    Ok(name)
}

pub fn parse_data_to_dns_message(data: &[u8], used_by_tcp: bool) -> std::io::Result<Message> {
    if used_by_tcp {
        if data.len() < 2 {
            return Err(Error::new(UnexpectedEof, "invalid dns data"));
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = data.get(2..len + 2).ok_or(Error::new(UnexpectedEof, "invalid dns data"))?;
        return parse_data_to_dns_message(data, false);
    }
    let message = Message::from_vec(data).map_err(|e| Error::new(InvalidData, e))?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::Query,
        rr::RecordType,
    };

    fn dns_query_message(domain: &str) -> Message {
        let name = Name::from_utf8(domain).expect("valid UTF-8 domain");
        let mut message = Message::new(0, hickory_proto::op::MessageType::Query, hickory_proto::op::OpCode::Query);
        message.add_query(Query::query(name, RecordType::A));
        message
    }

    #[test]
    fn extract_domain_returns_punycode_for_idn_domains() {
        let cases = [
            ("пример.рф", "xn--e1afmkfd.xn--p1ai"),
            ("тест.рус", "xn--e1aybc.xn--p1acf"),
        ];

        for (utf8_domain, expected_ascii) in cases {
            let message = dns_query_message(utf8_domain);
            let extracted = extract_domain_from_dns_message(&message).expect("domain extraction");
            assert_eq!(extracted, expected_ascii, "domain: {utf8_domain}");
            assert!(
                extracted.is_ascii(),
                "expected ASCII punycode for {utf8_domain}, got {extracted}"
            );
        }
    }

    #[test]
    fn extract_domain_preserves_ascii_domains() {
        let message = dns_query_message("example.com");
        let extracted = extract_domain_from_dns_message(&message).expect("domain extraction");
        assert_eq!(extracted, "example.com");
    }
}
