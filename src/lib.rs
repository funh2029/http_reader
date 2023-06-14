/*********************************************************
**
** Copyright (C) 2023 Funh2029. All rights reserved.
**
**
** GNU Lesser General Public License Usage
**
** Alternatively, this file may be used for
** non-commercial projects under the terms of the GNU
** Lesser General Public License version 3 as published
** by the Free Software Foundation:
**
**         https://www.gnu.org/licenses/lgpl-3.0.html
**
** The above copyright notice and this permission
** notice shall be included in all copies or substantial
** portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
** ANY KIND, OF MERCHANTABILITY, EXPRESS OR IMPLIED,
** INCLUDING BUT NOT LIMITED TO THE WARRANTIES FITNESS
** FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
** IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
** LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
** WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
** ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
** OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
**
*********************************************************/
use reqwest::{blocking::{RequestBuilder, Response}};
use std::{io::{self, SeekFrom}};
use std::str::FromStr;

use lru_cache::LruCache;

//use debug_print::{
//    debug_print as dprint,
//    debug_println as dprintln,
//    debug_eprint as deprint,
//    debug_eprintln as deprintln,
//};

///
/// min req size
///
const CHUNK_SIZE: usize = 2048;
const CACHE_COUNT: usize = 16;
const FRAGMENT_MAX:usize = CHUNK_SIZE/10;

pub struct HttpReader {
    // url: String,
    len: usize,
    etag: String,
    pos: u64,
    reqbuilder: RequestBuilder,
    cache: LruCache<usize, Vec<u8>>,
    }

impl HttpReader {
    pub fn new(url:&str) -> io::Result<Self> {
        let (len, etag) = get_file_size(url)?;
        Ok(Self {
            len,
            etag,
            pos: 0,
            reqbuilder: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                // .proxy(reqwest::Proxy::http("http://192.168.0.102:8888")?)
                .build().unwrap().request(reqwest::Method::GET, url),
            cache: LruCache::new(CACHE_COUNT),
            })
        }

    fn get_file_with_range(&mut self, range_start: usize, range_size: usize) -> io::Result<Response> {
        let res = self.reqbuilder.try_clone().unwrap()
            .header("Range", format!("bytes={}-{}", range_start, range_start + range_size - 1))
            .send().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        if ! res.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("Server Error: {} (pos:{} size:{})", res.status(), range_start, range_start + range_size - 1)));
            }

        let etag = res.headers().get("etag")
            .ok_or(io::Error::new(io::ErrorKind::NotFound, format!("Response doesn't include the ETag")))
            ?.to_str().map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid ETag header"))?;

        if self.etag != etag {
            Err(io::Error::new(io::ErrorKind::Other, "Server: File Modified - ETag Changed"))
            }
        else{
            Ok(res)
            }
        }
    }

impl io::Read for HttpReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let pos = self.pos as usize;
        let remaining = self.len - pos;
        if remaining == 0 || buf.len() == 0 {
            //println!(" ... [OK]");
            return Ok(0);
        }

        let len = std::cmp::min(buf.len(), remaining as usize) as usize;

        //dprint!("read pos = {}, len = {}", self.pos, len);
        if len < CHUNK_SIZE {
            // use cache
            let index = pos / CHUNK_SIZE;
            let offset_start = pos % CHUNK_SIZE;
            if let Some(chunk) = self.cache.get_mut(&index) {
                // hit
                //dprint!(" [hit] idx = {}, offset = {} ", index, offset_start);
                let bytes_to_read = std::cmp::min(len, chunk.len() as usize - offset_start);
                buf[..bytes_to_read].copy_from_slice(&chunk[offset_start..(offset_start + bytes_to_read)]);
                self.pos += bytes_to_read as u64;
                return Ok(bytes_to_read + self.read(&mut buf[bytes_to_read..])?);
                }
            else if len < FRAGMENT_MAX {
                // add new to cache
                let pos_at_chunk_start = (index*CHUNK_SIZE as usize) as usize;
                let bytes_to_read = std::cmp::min(self.len - pos_at_chunk_start, CHUNK_SIZE as usize);
                //dprint!(" [GET] Range({}, {}) to cache idx {}. ", pos_at_chunk_start, pos_at_chunk_start + bytes_to_read, index);

                let mut res = self.get_file_with_range(pos_at_chunk_start, bytes_to_read)?;
                let mut chunk = vec![0; bytes_to_read];
                res.read_exact(&mut chunk[..]).ok();
                self.cache.insert(index, chunk);
                return self.read(&mut buf[..]);
                }
            else{
                // read directly
                }
            }

        // println!("read pos = {}, len = {}", self.pos, len);

        // read directly
        //dprintln!(" ... [GET]");

        let mut res = self.get_file_with_range(self.pos as usize, len as usize)?;
        res.read_exact(buf).ok();
        self.pos += len as u64;
        Ok(len as usize)
        }
    }

impl io::Seek for HttpReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(new_pos) => {
                if new_pos <= self.len as u64 {
                    self.pos = new_pos;
                    Ok(new_pos)
                    }
                else{
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Cannot seek past end of data",
                        ))
                    }
                }
            SeekFrom::End(offset) => {
                if self.pos as i64 + offset <= self.len as i64 {
                    self.pos = (self.len as i64 + offset) as u64;
                    Ok((self.pos) as u64)
                    }
                else{
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Cannot seek past end of data",
                        ))
                    }
                }
            SeekFrom::Current(offset) => {
                let new_pos = (self.pos as i64 + offset) as usize;
                if new_pos <= self.len {
                    self.pos = new_pos as u64;
                    Ok((self.pos) as u64)
                    }
                else{
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Cannot seek past end of data",
                        ))
                    }
                }
            }
        }
    }

pub fn get_file_size(url: &str) -> Result<(usize, String), std::io::Error>  {
    let res = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        // .proxy(reqwest::Proxy::http("http://192.168.0.102:8888").unwrap())
        .build().unwrap()
        .request(reqwest::Method::HEAD, url)
        .send().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let length = res.headers().get("content-length")
        .ok_or(io::Error::new(io::ErrorKind::NotFound, format!("response doesn't include the content length")))?
        .to_str().map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid Content-Length header"))?;

    let length = usize::from_str(length).map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid Content-Length header"))?;

    let etag = res.headers().get("etag")
        .ok_or(io::Error::new(io::ErrorKind::NotFound, format!("Server file not found. (ETag not included)")))
        ?.to_str().map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid ETag header"))?;

    Ok((length, String::from(etag)))
    }

pub fn get_file_with_range(url: &str, range_start: usize, range_end: usize) -> Result<reqwest::blocking::Response, std::io::Error> {
    let res = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        // .proxy(reqwest::Proxy::http("http://192.168.0.102:8888").unwrap())
        .build().unwrap()
        .request(reqwest::Method::GET, url).header("Range", format!("bytes={}-{}", range_start, range_end))
        .send().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let status = res.status();
    if !(status == reqwest::StatusCode::PARTIAL_CONTENT) {
        Err(io::Error::new(io::ErrorKind::NotFound, format!("Unexpected server response: {}", status)))
        }
    else{
        Ok(res)
        }
    }

pub fn get_file_with_size(url: &str, range_start: usize, range_size: usize) -> Result<reqwest::blocking::Response, std::io::Error> {
    Ok(get_file_with_range(url, range_start, range_start + range_size - 1)?)
    }


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
    }
}
