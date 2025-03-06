pub(crate) mod stream;

pub struct StdReader<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut std::task::Context<'b>,
}

impl<'a, 'b, T: futures_io::AsyncRead + Unpin> StdReader<'a, 'b, T> {
    pub fn new(io: &'a mut T, cx: &'a mut std::task::Context<'b>) -> Self {
        Self { io, cx }
    }
}

impl<'a, 'b, T: futures_io::AsyncRead + Unpin> std::io::Read for StdReader<'a, 'b, T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use futures_io::AsyncRead;
        match std::pin::Pin::new(&mut self.io).poll_read(self.cx, buf) {
            std::task::Poll::Ready(result) => result,
            std::task::Poll::Pending => Err(std::io::ErrorKind::WouldBlock.into()),
        }
    }
}
