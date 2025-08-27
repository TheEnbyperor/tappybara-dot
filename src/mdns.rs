use alloc::string::ToString;
use rand::RngCore;

pub async fn get_server(stack: embassy_net::Stack<'_>) -> embassy_net::IpEndpoint {
    const MDNS_ENDPOINT: embassy_net::IpEndpoint = embassy_net::IpEndpoint::new(
        embassy_net::IpAddress::v6(0xFF02, 0, 0, 0, 0, 0, 0, 0xFB),
        5353,
    );

    let mut rx_metadata = [embassy_net::udp::PacketMetadata::EMPTY; 4];
    let mut rx_buffer = [0; 1500];
    let mut tx_metadata = [embassy_net::udp::PacketMetadata::EMPTY; 4];
    let mut tx_buffer = [0; 1500];

    'outer: loop {
        let mut socket = embassy_net::udp::UdpSocket::new(
            stack,
            &mut rx_metadata,
            &mut rx_buffer,
            &mut tx_metadata,
            &mut tx_buffer,
        );
        socket.bind(5353).unwrap();
        stack
            .join_multicast_group(MDNS_ENDPOINT.addr)
            .unwrap();

        let mdns_label = hickory_proto::rr::Name::from_ascii("_vas-coaps._udp.local.").unwrap();
        let mdns_unicast_class = hickory_proto::rr::DNSClass::Unknown(
            u16::from(hickory_proto::rr::DNSClass::IN) | 0x8000,
        );
        let mut mdns_query = hickory_proto::op::Query::new();
        mdns_query.set_query_class(mdns_unicast_class);
        mdns_query.set_query_type(hickory_proto::rr::RecordType::PTR);
        mdns_query.set_name(mdns_label.clone());
        let mut mdns_msg = hickory_proto::op::Message::new();
        mdns_msg.set_id(0);
        mdns_msg.set_message_type(hickory_proto::op::MessageType::Query);
        mdns_msg.set_recursion_desired(false);
        mdns_msg.add_query(mdns_query);

        debug!("Sending query: {:?}", mdns_msg);
        let mdns_msg_bytes = mdns_msg.to_vec().unwrap();
        socket
            .send_to(&mdns_msg_bytes, MDNS_ENDPOINT)
            .await
            .unwrap();

        let mut mdns_ticker = embassy_time::Ticker::every(embassy_time::Duration::from_secs(1));
        let mut mdns_done = embassy_time::Timer::after_secs(5);
        let mut mdns_targets = alloc::collections::BTreeSet::new();
        let mut mdns_srv: alloc::collections::BTreeMap<
            alloc::string::String,
            alloc::vec::Vec<hickory_proto::rr::rdata::SRV>,
        > = alloc::collections::BTreeMap::new();
        let mut mdns_aaaa: alloc::collections::BTreeMap<
            hickory_proto::rr::Name,
            alloc::collections::BTreeSet<hickory_proto::rr::rdata::aaaa::Ipv6Addr>,
        > = alloc::collections::BTreeMap::new();

        let mut data_buf = [0; 1500];
        loop {
            let res = embassy_futures::select::select3(
                mdns_ticker.next(),
                socket.recv_from(&mut data_buf),
                core::pin::Pin::new(&mut mdns_done),
            )
                .await;
            match res {
                embassy_futures::select::Either3::First(()) => {
                    debug!("Sending query: {:?}", mdns_msg);
                    let mdns_msg_bytes = mdns_msg.to_vec().unwrap();
                    socket
                        .send_to(&mdns_msg_bytes, MDNS_ENDPOINT)
                        .await
                        .unwrap();
                }
                embassy_futures::select::Either3::Second(Ok((n, _))) => {
                    let res_data = &data_buf[0..n];
                    if let Ok(mut msg) = hickory_proto::op::Message::from_vec(res_data) {
                        debug!("Got message: {:?}", msg);
                        if msg.authoritative()
                            && msg.id() == 0
                            && msg.message_type() == hickory_proto::op::MessageType::Response
                            && msg.op_code() == hickory_proto::op::OpCode::Query
                            && msg.response_code() == hickory_proto::op::ResponseCode::NoError
                        {
                            for answer in msg.take_answers() {
                                if answer.dns_class() == hickory_proto::rr::DNSClass::IN
                                    && answer.name() == &mdns_label
                                    && answer.record_type() == hickory_proto::rr::RecordType::PTR
                                {
                                    mdns_msg.add_answer(answer.clone());
                                    let service_name = answer.into_data().into_ptr().unwrap().0;
                                    if mdns_label.zone_of(&service_name)
                                        && service_name.num_labels() == mdns_label.num_labels() + 1
                                    {
                                        if let Ok(name) = alloc::str::from_utf8(
                                            service_name.iter().next().unwrap(),
                                        ) {
                                            mdns_targets.insert(name.to_string());
                                        }
                                    }
                                } else if (answer.dns_class() == hickory_proto::rr::DNSClass::IN
                                    || answer.dns_class() == mdns_unicast_class)
                                    && answer.record_type() == hickory_proto::rr::RecordType::AAAA
                                {
                                    mdns_msg.add_answer(answer.clone());
                                    let s = mdns_aaaa
                                        .entry(answer.name().clone())
                                        .or_insert_with(|| alloc::collections::BTreeSet::new());
                                    s.insert(answer.into_data().into_aaaa().unwrap().0);
                                }
                            }
                            for additional in msg.additionals() {
                                if additional.dns_class() == hickory_proto::rr::DNSClass::IN
                                    && mdns_label.zone_of(additional.name())
                                    && additional.record_type()
                                    == hickory_proto::rr::RecordType::SRV
                                {
                                    let d = additional.data().as_srv().unwrap();
                                    let has_aaaa = match msg
                                        .additionals()
                                        .iter()
                                        .filter(|a| {
                                            a.dns_class() == hickory_proto::rr::DNSClass::IN
                                                && a.name() == additional.name()
                                                && a.record_type()
                                                == hickory_proto::rr::RecordType::NSEC
                                        })
                                        .next()
                                    {
                                        Some(a) => {
                                            let (_, data) = a.data().as_unknown().unwrap();
                                            if data.anything().len() < 4 {
                                                true
                                            } else {
                                                let block_window = data.anything()[2];
                                                let window_len = data.anything()[3];
                                                if block_window != 0
                                                    || window_len < 1
                                                    || window_len > 32
                                                    || data.anything().len()
                                                    < window_len as usize + 4
                                                {
                                                    true
                                                } else {
                                                    let record_types = (&data.anything()[4..])
                                                        .iter()
                                                        .enumerate()
                                                        .flat_map(|(i, v)| {
                                                            (0..8).filter_map(move |j| {
                                                                if *v & (1 << (7 - j)) != 0 {
                                                                    Some(j + (i * 8))
                                                                } else {
                                                                    None
                                                                }
                                                            })
                                                        })
                                                        .map(|v| {
                                                            hickory_proto::rr::RecordType::from(
                                                                v as u16,
                                                            )
                                                        })
                                                        .collect::<alloc::vec::Vec<_>>();
                                                    let has_aaaa = record_types.contains(
                                                        &hickory_proto::rr::RecordType::AAAA,
                                                    );
                                                    has_aaaa
                                                }
                                            }
                                        }
                                        None => true,
                                    };
                                    if has_aaaa {
                                        let mut target_addr_query = hickory_proto::op::Query::new();
                                        target_addr_query.set_query_class(
                                            hickory_proto::rr::DNSClass::Unknown(
                                                u16::from(hickory_proto::rr::DNSClass::IN) | 0x8000,
                                            ),
                                        );
                                        target_addr_query
                                            .set_query_type(hickory_proto::rr::RecordType::AAAA);
                                        target_addr_query.set_name(d.target().clone());
                                        if !mdns_msg.queries().contains(&target_addr_query) {
                                            mdns_msg.add_query(target_addr_query);
                                        }
                                    }
                                }
                            }
                            for additional in msg.take_additionals() {
                                if additional.dns_class() == hickory_proto::rr::DNSClass::IN
                                    && mdns_label.zone_of(additional.name())
                                    && additional.name().num_labels() == mdns_label.num_labels() + 1
                                {
                                    mdns_msg.add_answer(additional.clone());
                                    if additional.record_type()
                                        == hickory_proto::rr::RecordType::SRV
                                    {
                                        if let Ok(name) = alloc::str::from_utf8(
                                            additional.name().iter().next().unwrap(),
                                        ) {
                                            let s = mdns_srv
                                                .entry(name.to_string())
                                                .or_insert_with(|| alloc::vec::Vec::new());
                                            let d = additional.into_data().into_srv().unwrap();
                                            if !s.contains(&d) {
                                                s.push(d);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                embassy_futures::select::Either3::Second(Err(e)) => {
                    warn!("Error receiving mDNS response: {:?}", e);
                    continue 'outer;
                }
                embassy_futures::select::Either3::Third(()) => {
                    break;
                }
            }
        }

        stack
            .leave_multicast_group(MDNS_ENDPOINT.addr)
            .unwrap();
        socket.close();

        let viable_targets = mdns_targets
            .into_iter()
            .filter(|t| mdns_srv.contains_key(t))
            .collect::<alloc::vec::Vec<_>>();
        if viable_targets.is_empty() {
            continue;
        }
        let mut rand = [0u8; 2];
        unsafe { crate::RAND.lock().await.assume_init_mut() }.fill_bytes(&mut rand);
        let target_index = rand[0] as usize % viable_targets.len();
        let target = &viable_targets[target_index];
        info!("Connecting to server: {}", target);
        let mut srv_records = mdns_srv.remove(target).unwrap();
        srv_records.sort_by_key(|srv| srv.priority());
        let target_srv = &srv_records[0];
        let address = match mdns_aaaa.get(target_srv.target()) {
            Some(addrs) => {
                let addr_index = rand[1] as usize % addrs.len();
                *addrs.iter().skip(addr_index).next().unwrap()
            }
            None => continue,
        };
        return embassy_net::IpEndpoint::new(address.into(), target_srv.port());
    }
}
