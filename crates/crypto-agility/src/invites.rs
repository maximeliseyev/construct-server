use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Invite token object for one-time contact sharing
/// 
/// This structure is cryptographically signed by the user's Identity Key
/// and can be encoded into QR codes or deep links for secure contact exchange.
/// 
/// Security properties:
/// - One-time use only (jti tracking prevents replay)
/// - Short TTL (5 minutes for QR, configurable for links)
/// - Cryptographic authenticity (Ed25519 signature)
/// - Federation-ready (includes server FQDN)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteToken {
    /// Protocol version (currently 1)
    pub v: u32,
    
    /// Unique invite ID (JWT jti) - prevents replay attacks
    pub jti: Uuid,
    
    /// User UUID who created this invite
    pub uuid: Uuid,
    
    /// Server FQDN (e.g., "konstruct.cc") for federation
    pub server: String,
    
    /// Ephemeral X25519 public key (Base64 encoded)
    /// Generated fresh for each invite, never reused
    #[serde(rename = "ephKey")]
    pub eph_key: String,
    
    /// Unix timestamp when this invite was created
    pub ts: i64,
    
    /// Ed25519 signature over canonical form of (v, jti, uuid, server, ephKey, ts)
    /// Signed with user's long-term Identity Key
    pub sig: String,
}

impl InviteToken {
    /// Create canonical string for signing
    /// 
    /// Format: "{v}|{jti}|{uuid}|{server}|{ephKey}|{ts}"
    /// This ensures consistent signing/verification across implementations
    pub fn canonical_string(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.v, self.jti, self.uuid, self.server, self.eph_key, self.ts
        )
    }
    
    /// Check if invite is expired
    /// 
    /// Default TTL: 5 minutes (300 seconds)
    pub fn is_expired(&self, ttl_seconds: i64) -> bool {
        let now = Utc::now().timestamp();
        (now - self.ts) > ttl_seconds
    }
    
    /// Check if timestamp is in the future (clock skew attack)
    pub fn is_future(&self) -> bool {
        let now = Utc::now().timestamp();
        self.ts > (now + 60) // Allow 60s clock skew
    }
}

/// Database record for invite token tracking
#[derive(Debug, Clone)]
pub struct InviteTokenRecord {
    pub jti: Uuid,
    pub user_id: Uuid,
    pub ephemeral_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_string() {
        let invite = InviteToken {
            v: 1,
            jti: Uuid::parse_str("25a5e378-c873-4e4b-a16a-a8d299386d3d").unwrap(),
            uuid: Uuid::parse_str("af70cf9a-b176-4df3-b6bf-00196a6f173e").unwrap(),
            server: "konstruct.cc".to_string(),
            eph_key: "test_key_base64".to_string(),
            ts: 1675209600,
            sig: "test_sig".to_string(),
        };

        let canonical = invite.canonical_string();
        assert!(canonical.contains("1|"));
        assert!(canonical.contains("|konstruct.cc|"));
        assert!(canonical.contains("|1675209600"));
    }

    #[test]
    fn test_is_expired() {
        let old_invite = InviteToken {
            v: 1,
            jti: Uuid::new_v4(),
            uuid: Uuid::new_v4(),
            server: "test.com".to_string(),
            eph_key: "key".to_string(),
            ts: Utc::now().timestamp() - 400, // 400 seconds ago
            sig: "sig".to_string(),
        };

        assert!(old_invite.is_expired(300)); // 5 min TTL
        assert!(!old_invite.is_expired(500)); // 8.3 min TTL
    }

    #[test]
    fn test_is_future() {
        let future_invite = InviteToken {
            v: 1,
            jti: Uuid::new_v4(),
            uuid: Uuid::new_v4(),
            server: "test.com".to_string(),
            eph_key: "key".to_string(),
            ts: Utc::now().timestamp() + 200, // 200 seconds in future
            sig: "sig".to_string(),
        };

        assert!(future_invite.is_future());
    }
}
