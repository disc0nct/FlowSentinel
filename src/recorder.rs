use std::fs::File;
use std::sync::{Arc, Mutex};
use pcap_file::pcap::PcapWriter;
use std::time::SystemTime;

#[derive(Clone)]
pub struct Recorder {
    writer: Arc<Mutex<PcapWriter<File>>>,
    pub file_path: String,
}

impl Recorder {
    pub fn new(path: &str) -> anyhow::Result<Self> {
        let file = File::create(path)?;
        let writer = PcapWriter::new(file)?;
        Ok(Self {
            writer: Arc::new(Mutex::new(writer)),
            file_path: path.to_string(),
        })
    }

    pub fn write_packet(&self, packet: &[u8]) {
        if let Ok(mut writer) = self.writer.lock() {
            let ts = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
            // PcapWriter::write takes (ts_sec, ts_nsec, data, orig_len)
            let _ = writer.write(
                ts.as_secs() as u32,
                ts.subsec_nanos(),
                packet,
                packet.len() as u32
            );
        }
    }
}
