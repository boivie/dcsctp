use crate::socket::util::TxErrorCounter;

pub(crate) struct SocketMetrics {
    pub rx_packets_count: usize,
    pub tx_packets_count: usize,
    pub tx_messages_count: usize,
    pub tx_error_counter: TxErrorCounter,
}
