use rand::{Rng, RngCore};

struct CoAPTransmissionParameters {
    ack_timeout: embassy_time::Duration,
    ack_random_factor: f64,
    max_retransmit: usize,
    nstart: usize,
    default_leisure: embassy_time::Duration,
    probing_rate_bps: usize,
}

impl Default for CoAPTransmissionParameters {
    fn default() -> Self {
        Self {
            ack_timeout: embassy_time::Duration::from_secs(2),
            ack_random_factor: 1.5,
            max_retransmit: 4,
            nstart: 1,
            default_leisure: embassy_time::Duration::from_secs(5),
            probing_rate_bps: 1,
        }
    }
}

impl CoAPTransmissionParameters {
    async fn new_timeout(&self) -> embassy_time::Duration {
        let v = unsafe { crate::RAND.lock().await.assume_init_mut() }.random_range(
            self.ack_timeout.as_millis() as f64
                ..self.ack_timeout.as_millis() as f64 * self.ack_random_factor,
        );
        embassy_time::Duration::from_millis(v as u64)
    }

    fn max_transmit_span(&self) -> embassy_time::Duration {
        self.ack_timeout
            * ((((2_i64.pow(self.max_retransmit as u32)) - 1) as f64) * self.ack_random_factor)
                as u32
    }

    fn max_transmit_wait(&self) -> embassy_time::Duration {
        self.ack_timeout
            * ((((2_i64.pow(self.max_retransmit as u32 + 1)) - 1) as f64) * self.ack_random_factor)
                as u32
    }
}

pub struct CoAPConnection<'a> {
    tls_connection: crate::tls::Connection<'a>,
    transmission_parameters: CoAPTransmissionParameters,
    in_flight: alloc::collections::BTreeMap<u16, InFlightPacket>,
    ping_in_flight: bool,
    send_queue: alloc::collections::VecDeque<coap_lite::Packet>,
    next_message_id: u16,
    channel: alloc::sync::Arc<CoAPConnectionChannel>,
}

#[derive(Debug)]
struct InFlightPacket {
    packet: coap_lite::Packet,
    first_transmitted: embassy_time::Instant,
    timeout: embassy_time::Duration,
    timeout_at: embassy_time::Instant,
    retransmission_count: usize,
    is_ping: bool,
}

struct CoAPConnectionChannel {
    packets_send: embassy_sync::channel::Channel<
        embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
        coap_lite::Packet,
        5,
    >,
    packets_recv: embassy_sync::channel::Channel<
        embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
        coap_lite::Packet,
        5,
    >,
}

#[derive(Debug, Clone)]
pub struct CoAPConnectionHandle {
    channel: alloc::sync::Weak<CoAPConnectionChannel>,
}

#[derive(Debug, Copy, Clone)]
pub enum CoAPConnectionError {
    TLSError(i32),
    PingTimeout,
}

impl<'a> CoAPConnection<'a> {
    pub fn new(tls_connection: crate::tls::Connection<'a>) -> Self {
        Self {
            tls_connection,
            transmission_parameters: CoAPTransmissionParameters::default(),
            in_flight: alloc::collections::BTreeMap::new(),
            ping_in_flight: false,
            send_queue: alloc::collections::VecDeque::new(),
            next_message_id: 0,
            channel: alloc::sync::Arc::new(CoAPConnectionChannel {
                packets_send: embassy_sync::channel::Channel::new(),
                packets_recv: embassy_sync::channel::Channel::new(),
            }),
        }
    }

    pub fn handle(&self) -> CoAPConnectionHandle {
        CoAPConnectionHandle {
            channel: alloc::sync::Arc::downgrade(&self.channel),
        }
    }

    pub async fn run(&mut self) -> Result<(), CoAPConnectionError> {
        let mut last_ping = embassy_time::Instant::now();
        loop {
            let next_ping = last_ping + embassy_time::Duration::from_secs(10);
            let mut next_timeout = self
                .in_flight
                .iter()
                .map(|(k, v)| (k, v.timeout_at))
                .collect::<alloc::vec::Vec<_>>();
            next_timeout.sort();
            let next_timeout = next_timeout
                .into_iter()
                .next()
                .map(|(k, timeout)| (*k, embassy_time::Timer::at(timeout)));

            if let Some((timeout_packet, timeout)) = next_timeout {
                match embassy_futures::select::select4(
                    self.tls_connection.read_data(),
                    self.channel.packets_send.receive(),
                    timeout,
                    embassy_time::Timer::at(next_ping),
                )
                .await
                {
                    embassy_futures::select::Either4::First(Ok(data)) => {
                        if let Err(e) = self.handle_incoming_data(data).await {
                            let _ = self.tls_connection.shutdown().await;
                            return Err(e);
                        }
                    }
                    embassy_futures::select::Either4::First(Err(e)) => {
                        let _ = self.tls_connection.shutdown().await;
                        return Err(CoAPConnectionError::TLSError(e));
                    }
                    embassy_futures::select::Either4::Second(packet) => {
                        if let Err(e) = self.handle_outgoing_packet(packet).await {
                            let _ = self.tls_connection.shutdown().await;
                            return Err(e);
                        }
                    }
                    embassy_futures::select::Either4::Third(()) => {
                        if let Err(e) = self.handle_retransmit_timeout(timeout_packet).await {
                            let _ = self.tls_connection.shutdown().await;
                            return Err(e);
                        }
                    }
                    embassy_futures::select::Either4::Fourth(()) => {
                        last_ping = next_ping;
                        if let Err(e) = self.handle_ping().await {
                            let _ = self.tls_connection.shutdown().await;
                            return Err(e);
                        }
                    }
                }
            } else {
                match embassy_futures::select::select3(
                    self.tls_connection.read_data(),
                    self.channel.packets_send.receive(),
                    embassy_time::Timer::at(next_ping),
                )
                .await
                {
                    embassy_futures::select::Either3::First(Ok(data)) => {
                        if let Err(e) = self.handle_incoming_data(data).await {
                            let _ = self.tls_connection.shutdown().await;
                            return Err(e);
                        }
                    }
                    embassy_futures::select::Either3::First(Err(e)) => {
                        let _ = self.tls_connection.shutdown().await;
                        return Err(CoAPConnectionError::TLSError(e));
                    }
                    embassy_futures::select::Either3::Second(packet) => {
                        if let Err(e) = self.handle_outgoing_packet(packet).await {
                            let _ = self.tls_connection.shutdown().await;
                            return Err(e);
                        }
                    }
                    embassy_futures::select::Either3::Third(()) => {
                        last_ping = next_ping;
                        if let Err(e) = self.handle_ping().await {
                            let _ = self.tls_connection.shutdown().await;
                            return Err(e);
                        }
                    }
                }
            }
        }
    }

    async fn handle_incoming_data(
        &mut self,
        data: alloc::vec::Vec<u8>,
    ) -> Result<(), CoAPConnectionError> {
        match coap_lite::Packet::from_bytes(&data) {
            Ok(packet) => {
                debug!("Received packet: {:?}", packet);
                match packet.header.get_type() {
                    coap_lite::MessageType::Confirmable => {
                        let mut ack_packet = coap_lite::Packet::new();
                        ack_packet.header.code = coap_lite::MessageClass::Empty;
                        ack_packet.header.message_id = packet.header.message_id;
                        ack_packet
                            .header
                            .set_type(coap_lite::MessageType::Acknowledgement);
                        let ack_packet_data = match ack_packet.to_bytes() {
                            Ok(data) => data,
                            Err(e) => {
                                warn!("Unable to serialise CoAP ack packet: {:?}", e);
                                return Ok(());
                            }
                        };
                        debug!("Sending ack packet: {:?}", ack_packet);
                        self.tls_connection
                            .write_data(&ack_packet_data)
                            .await
                            .map_err(CoAPConnectionError::TLSError)?;
                    }
                    coap_lite::MessageType::NonConfirmable => {}
                    coap_lite::MessageType::Acknowledgement => {
                        if let Some(packet) = self.in_flight.remove(&packet.header.message_id) {
                            debug!("Packet acknowledged: {:?}", packet);
                            if packet.is_ping {
                                self.ping_in_flight = false;
                            }
                            self.try_drain_send_queue().await?;
                        }
                    }
                    coap_lite::MessageType::Reset => {
                        if let Some(packet) = self.in_flight.remove(&packet.header.message_id) {
                            debug!("Packet reset: {:?}", packet);
                            if packet.is_ping {
                                self.ping_in_flight = false;
                            }
                            self.try_drain_send_queue().await?;
                        }
                    }
                }
                if packet.header.code != coap_lite::MessageClass::Empty {
                    self.channel.packets_recv.send(packet).await;
                }
            }
            Err(e) => {
                warn!("Failed to parse incoming packet, ignoring: {:?}", e);
            }
        }
        Ok(())
    }

    async fn handle_outgoing_packet(
        &mut self,
        packet: coap_lite::Packet,
    ) -> Result<(), CoAPConnectionError> {
        if self.in_flight.len() >= self.transmission_parameters.nstart {
            self.send_queue.push_back(packet);
            return Ok(());
        }
        self.transmit_packet(packet, false).await
    }

    async fn transmit_packet(
        &mut self,
        mut packet: coap_lite::Packet,
        is_ping: bool,
    ) -> Result<(), CoAPConnectionError> {
        packet.header.message_id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        let packet_data = match packet.to_bytes() {
            Ok(data) => data,
            Err(e) => {
                warn!("Unable to serialise CoAP packet: {:?}", e);
                return Ok(());
            }
        };
        debug!("Sending packet: {:?}", packet);
        self.tls_connection
            .write_data(&packet_data)
            .await
            .map_err(CoAPConnectionError::TLSError)?;
        let now = embassy_time::Instant::now();
        let timeout = self.transmission_parameters.new_timeout().await;
        let packet = InFlightPacket {
            packet,
            timeout_at: now + timeout,
            first_transmitted: now,
            timeout,
            retransmission_count: 0,
            is_ping,
        };
        self.in_flight
            .insert(packet.packet.header.message_id, packet);

        Ok(())
    }

    async fn try_drain_send_queue(&mut self) -> Result<(), CoAPConnectionError> {
        if self.in_flight.len() < self.transmission_parameters.nstart {
            if let Some(packet) = self.send_queue.pop_front() {
                self.transmit_packet(packet, false).await?;
            }
        }
        Ok(())
    }

    async fn handle_retransmit_timeout(
        &mut self,
        message_id: u16,
    ) -> Result<(), CoAPConnectionError> {
        let mut packet = self.in_flight.get_mut(&message_id).unwrap();
        let is_ping = packet.is_ping;
        if packet.retransmission_count < self.transmission_parameters.max_retransmit {
            packet.retransmission_count += 1;
            packet.timeout *= 2;
            packet.timeout_at = embassy_time::Instant::now() + packet.timeout;
            let packet_data = match packet.packet.to_bytes() {
                Ok(data) => data,
                Err(e) => {
                    warn!("Unable to serialise CoAP packet: {:?}", e);
                    self.in_flight.remove(&message_id);
                    self.try_drain_send_queue().await?;
                    if is_ping {
                        self.ping_in_flight = false;
                    }
                    return Ok(());
                }
            };
            self.tls_connection
                .write_data(&packet_data)
                .await
                .map_err(CoAPConnectionError::TLSError)?;
        } else {
            warn!("Max retransmissions, packet lost");
            if is_ping {
                return Err(CoAPConnectionError::PingTimeout);
            }
            self.in_flight.remove(&message_id);
            self.try_drain_send_queue().await?;
        }
        Ok(())
    }

    async fn handle_ping(&mut self) -> Result<(), CoAPConnectionError> {
        if !self.ping_in_flight {
            let mut ping_packet = coap_lite::Packet::new();
            ping_packet.header.code = coap_lite::MessageClass::Empty;
            ping_packet
                .header
                .set_type(coap_lite::MessageType::Confirmable);
            self.transmit_packet(ping_packet, true).await?;
            self.ping_in_flight = true;
        }
        Ok(())
    }
}

type PacketChannel = embassy_sync::channel::Channel<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    coap_lite::Packet,
    1,
>;
type PacketRegistry = alloc::sync::Arc<
    embassy_sync::mutex::Mutex<
        embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
        alloc::collections::BTreeMap<
            alloc::vec::Vec<u8>,
            alloc::sync::Arc<PacketChannel>,
        >,
    >,
>;

#[derive(Clone)]
pub struct CoAPClient {
    connection: CoAPConnectionHandle,
    packets: PacketRegistry,
}

#[derive(Debug, Clone)]
pub enum CoAPError {
    ConnectionClosed,
    RequestTimeout,
}

impl CoAPClient {
    pub async fn new(handle: CoAPConnectionHandle) -> Self {
        let spawner = embassy_executor::Spawner::for_current_executor().await;
        let c = Self {
            connection: handle,
            packets: alloc::sync::Arc::new(embassy_sync::mutex::Mutex::new(
                alloc::collections::BTreeMap::new(),
            )),
        };
        spawner
            .spawn(run_coap_client(c.connection.clone(), c.packets.clone()))
            .unwrap();
        c
    }

    async fn send_packet(&self, mut packet: coap_lite::Packet) -> Result<(alloc::sync::Arc<PacketChannel>, alloc::vec::Vec<u8>), CoAPError> {
        let mut token = vec![0u8; 8];
        unsafe { crate::RAND.lock().await.assume_init_mut() }.fill_bytes(token.as_mut_slice());
        packet.set_token(token.clone());
        let chan = alloc::sync::Arc::new(embassy_sync::channel::Channel::new());
        self.packets
            .lock()
            .await
            .insert(token.clone(), chan.clone());
        loop {
            let Some(connection) = self.connection.channel.upgrade() else {
                self.packets.lock().await.remove(&token);
                return Err(CoAPError::ConnectionClosed);
            };
            if let Err(_) = embassy_time::with_timeout(
                embassy_time::Duration::from_millis(300),
                connection.packets_send.send(packet.clone()),
            )
                .await
            {
                continue;
            }
            break;
        }
        Ok((chan, token))
    }

    pub async fn send_request(&self, req: coap_lite::CoapRequest<()>) -> Result<coap_lite::CoapResponse, CoAPError> {
        let (chan, token)  = self.send_packet(req.message).await?;
        let res = embassy_time::with_timeout(
            embassy_time::Duration::from_secs(10),
            chan.receive()
        ).await;
        self.packets.lock().await.remove(&token);
        match res{
            Ok(resp) => {
                Ok(coap_lite::CoapResponse { message: resp })
            },
            Err(_) => Err(CoAPError::RequestTimeout)
        }
    }

    pub async fn send_observe_request(
        &self,
        mut req: coap_lite::CoapRequest<()>,
    ) -> Result<(coap_lite::CoapResponse, Option<CoAPObservation>), CoAPError> {
        req.message.add_option_as(coap_lite::CoapOption::Observe, coap_lite::option_value::OptionValueU8(0));
        let (chan, token)  = self.send_packet(req.message).await?;
        let res = embassy_time::with_timeout(
            embassy_time::Duration::from_secs(10),
            chan.receive()
        ).await;
        match res{
            Ok(resp) => {
                let resp = coap_lite::CoapResponse { message: resp };
                if resp.get_status().is_error() {
                    self.packets.lock().await.remove(&token);
                    return Ok((resp, None));
                }
                let observe = match resp.message.get_first_option_as::<coap_lite::option_value::OptionValueU32>(coap_lite::CoapOption::Observe)
                    .transpose().ok().and_then(|o| o) {
                    Some(seq) => Some(CoAPObservation {
                        packets: self.packets.clone(),
                        channel: alloc::sync::Arc::downgrade(&chan),
                        last_sequence: seq.0,
                        is_done: false,
                    }),
                    None => {
                        self.packets.lock().await.remove(&token);
                        None
                    }
                };

                Ok((resp, observe))
            },
            Err(_) => {
                self.packets.lock().await.remove(&token);
                Err(CoAPError::RequestTimeout)
            }
        }
    }
}

pub struct CoAPObservation {
    packets: PacketRegistry,
    channel: alloc::sync::Weak<PacketChannel>,
    last_sequence: u32,
    is_done: bool,
}

impl CoAPObservation {
    pub fn has_next(&self) -> bool {
        if self.is_done {
            return false;
        }
        let Some(chan) = self.channel.upgrade() else {
            return false;
        };
        !chan.is_empty()
    }

    pub async fn next(&mut self) -> Option<coap_lite::CoapResponse> {
        if self.is_done {
            return None;
        }
        loop {
            let Some(chan) = self.channel.upgrade() else {
                return None;
            };
            let Ok(resp) = embassy_time::with_timeout(
                embassy_time::Duration::from_millis(300),
                chan.receive(),
            )
                .await
            else {
                continue;
            };
            let resp = coap_lite::CoapResponse { message: resp };
            if resp.get_status().is_error() {
                self.packets.lock().await.remove(resp.message.get_token());
                self.is_done = true;
                return Some(resp);
            } else {
                let Some(seq) = resp.message.get_first_option_as::<coap_lite::option_value::OptionValueU32>(coap_lite::CoapOption::Observe)
                    .transpose().ok().and_then(|o| o) else {
                    self.packets.lock().await.remove(resp.message.get_token());
                    self.is_done = true;
                    return Some(resp);
                };
                if (self.last_sequence < seq.0 && seq.0 - self.last_sequence < 2_i32.pow(23) as u32) ||
                    (self.last_sequence > seq.0 && self.last_sequence - seq.0 > 2_i32.pow(23) as u32) {
                    self.last_sequence = seq.0;
                    return Some(resp);
                } else {
                    continue;
                }
            }
        }
    }
}

#[embassy_executor::task]
async fn run_coap_client(handle: CoAPConnectionHandle, packets: PacketRegistry) {
    loop {
        let Some(connection) = handle.channel.upgrade() else {
            return;
        };
        let Ok(resp) = embassy_time::with_timeout(
            embassy_time::Duration::from_millis(300),
            connection.packets_recv.receive(),
        )
        .await
        else {
            continue;
        };
        if let Some(chan) = packets.lock().await.get(resp.get_token()) {
            chan.send(resp).await;
        } else {
            let mut packet = coap_lite::Packet::new();
            packet.header.set_type(coap_lite::MessageType::Reset);
            packet.set_token(resp.get_token().to_vec());
            connection.packets_send.send(packet).await;
        }
    }
}
