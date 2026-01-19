use crate::collector::ProcessMetrics;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
struct ExportProcess {
    pid: u32,
    name: String,
    uid: u32,
    bytes_in: u64,
    bytes_out: u64,
    packets_in: u64,
    packets_out: u64,
    bytes_per_sec: f64,
    packets_per_sec: f64,
    connection_count: usize,
}

impl From<&ProcessMetrics> for ExportProcess {
    fn from(p: &ProcessMetrics) -> Self {
        Self {
            pid: p.pid,
            name: p.name.clone(),
            uid: p.uid,
            bytes_in: p.bytes_in,
            bytes_out: p.bytes_out,
            packets_in: p.packets_in,
            packets_out: p.packets_out,
            bytes_per_sec: p.bytes_per_sec,
            packets_per_sec: p.packets_per_sec,
            connection_count: p.connection_count,
        }
    }
}

pub fn to_json(processes: &[ProcessMetrics]) -> Result<String> {
    let export: Vec<ExportProcess> = processes.iter().map(|p| p.into()).collect();
    let json = serde_json::to_string_pretty(&export)?;
    Ok(json)
}

pub fn to_csv(processes: &[ProcessMetrics]) -> Result<String> {
    let mut wtr = csv::Writer::from_writer(vec![]);

    for process in processes {
        let export: ExportProcess = process.into();
        wtr.serialize(&export)?;
    }

    let data = wtr.into_inner()?;
    Ok(String::from_utf8(data)?)
}
