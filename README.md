```rust
use std::fs::File;
use zip::read::ZipArchive;
use http_reader::HttpReader;

fn main() -> Result<()> {
    let reader = HttpReader::new("http://192.168.0.102:9212/upgrade.zip").unwrap();
    let mut archive = ZipArchive::new(reader).unwrap();
    let mut file = archive.by_name("rootfs.emmc").unwrap();
    let mut fd = File::create("./rootfs.emmc").unwrap();
    io::copy(file, fd).unwrap();
    Ok(())
    }
```