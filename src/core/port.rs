use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Asynchronously probe TCP ports concurrently with a bounded semaphore and per-port timeout
pub async fn scan_ports(
    ip: Ipv4Addr,
    ports: Vec<u16>,
    timeout: Duration,
    semaphore: Arc<Semaphore>,
) -> (Ipv4Addr, Vec<u16>) {
    let mut tasks = JoinSet::new();

    for port in ports {
        let sem = Arc::clone(&semaphore);
        tasks.spawn(async move {
            let Ok(_permit) = sem.acquire().await else {
                return None;
            };
            let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
            if matches!(
                tokio::time::timeout(timeout, TcpStream::connect(&addr)).await,
                Ok(Ok(_))
            ) {
                Some(port)
            } else {
                None
            }
        });
    }

    let mut open_ports = Vec::new();
    while let Some(res) = tasks.join_next().await {
        if let Ok(Some(port)) = res {
            open_ports.push(port);
        }
    }
    open_ports.sort_unstable();
    (ip, open_ports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_concurrent_scan_ports() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = listener.local_addr().unwrap().port();
        let closed_port = if open_port < 65535 {
            open_port + 1
        } else {
            open_port - 1
        };

        let semaphore = Arc::new(Semaphore::new(10));
        let timeout = Duration::from_millis(200);

        let (ip, ports) = scan_ports(
            Ipv4Addr::LOCALHOST,
            vec![open_port, closed_port],
            timeout,
            semaphore,
        )
        .await;

        assert_eq!(ip, Ipv4Addr::LOCALHOST);
        assert_eq!(ports, vec![open_port]);
    }
}
