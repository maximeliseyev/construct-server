//! Redis Streams support

use crate::{RedisClient, Result};
use redis::{streams::StreamReadReply, AsyncCommands, Value};
use std::collections::HashMap;

/// Entry in a Redis Stream
#[derive(Debug, Clone)]
pub struct StreamEntry {
    pub id: String,
    pub fields: HashMap<String, String>,
}

/// Options for XREAD command
#[derive(Debug, Clone)]
pub struct StreamReadOptions {
    /// Block for N milliseconds (None = no blocking)
    pub block: Option<u64>,
    /// Maximum number of entries to return
    pub count: Option<u64>,
}

impl Default for StreamReadOptions {
    fn default() -> Self {
        Self {
            block: None,
            count: None,
        }
    }
}

impl RedisClient {
    // ============================================================================
    // Stream Operations
    // ============================================================================

    /// XADD - Add entry to stream
    ///
    /// Returns the generated ID
    pub async fn xadd<K, F>(&mut self, stream_key: K, id: &str, fields: &[(F, F)]) -> Result<String>
    where
        K: redis::ToRedisArgs + Send + Sync,
        F: redis::ToRedisArgs + Send + Sync,
    {
        self.connection_mut().xadd(stream_key, id, fields).await
    }

    /// XREAD - Read from one or more streams
    ///
    /// `streams` is a list of (key, id) pairs
    pub async fn xread(
        &mut self,
        streams: &[(&str, &str)],
        options: StreamReadOptions,
    ) -> Result<Vec<StreamEntry>> {
        let mut cmd = redis::cmd("XREAD");

        // Add options
        if let Some(count) = options.count {
            cmd.arg("COUNT").arg(count);
        }
        if let Some(block_ms) = options.block {
            cmd.arg("BLOCK").arg(block_ms);
        }

        // Add STREAMS keyword
        cmd.arg("STREAMS");

        // Add stream keys
        for (key, _) in streams {
            cmd.arg(*key);
        }

        // Add IDs
        for (_, id) in streams {
            cmd.arg(*id);
        }

        // Execute
        let reply: StreamReadReply = cmd.query_async(self.connection_mut()).await?;

        // Convert to simplified format
        let mut entries = Vec::new();
        for stream_key in reply.keys {
            for stream_id in stream_key.ids {
                let mut fields = HashMap::new();

                // Parse field map
                for (key, value) in stream_id.map.iter() {
                    // Keys are Strings, values are redis::Value
                    let value_str = match value {
                        Value::BulkString(bytes) => String::from_utf8_lossy(bytes).to_string(),
                        Value::SimpleString(s) => s.clone(),
                        Value::Int(i) => i.to_string(),
                        _ => continue, // Skip unsupported types
                    };
                    fields.insert(key.clone(), value_str);
                }

                entries.push(StreamEntry {
                    id: stream_id.id,
                    fields,
                });
            }
        }

        Ok(entries)
    }

    /// XACK - Acknowledge stream entries
    pub async fn xack<K, ID>(&mut self, stream_key: K, group: &str, ids: &[ID]) -> Result<i64>
    where
        K: redis::ToRedisArgs + Send + Sync,
        ID: redis::ToRedisArgs + Send + Sync,
    {
        self.connection_mut().xack(stream_key, group, ids).await
    }

    /// XDEL - Delete stream entries
    pub async fn xdel<K, ID>(&mut self, stream_key: K, ids: &[ID]) -> Result<i64>
    where
        K: redis::ToRedisArgs + redis::ToSingleRedisArg + Send + Sync,
        ID: redis::ToRedisArgs + Send + Sync,
    {
        self.connection_mut().xdel(stream_key, ids).await
    }

    /// XLEN - Get stream length
    pub async fn xlen<K>(&mut self, stream_key: K) -> Result<i64>
    where
        K: redis::ToRedisArgs + Send + Sync,
    {
        self.connection_mut().xlen(stream_key).await
    }

    /// XTRIM - Trim stream to approximate size
    pub async fn xtrim<K>(&mut self, stream_key: K, max_len: i64) -> Result<i64>
    where
        K: redis::ToRedisArgs + Send + Sync,
    {
        redis::cmd("XTRIM")
            .arg(stream_key)
            .arg("MAXLEN")
            .arg("~")
            .arg(max_len)
            .query_async(self.connection_mut())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_stream_operations() -> Result<()> {
        let mut client = RedisClient::connect("redis://localhost:6379").await?;

        let stream_key = "test_stream";

        // XADD
        let id1 = client
            .xadd(
                stream_key,
                "*",
                &[("field1", "value1"), ("field2", "value2")],
            )
            .await?;
        assert!(!id1.is_empty());

        // XLEN
        let len = client.xlen(stream_key).await?;
        assert_eq!(len, 1);

        // XREAD
        let entries = client
            .xread(&[(stream_key, "0")], StreamReadOptions::default())
            .await?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fields.get("field1"), Some(&"value1".to_string()));

        // XDEL
        client.xdel(stream_key, &[&id1]).await?;

        // Clean up
        client.del(stream_key).await?;

        Ok(())
    }
}
