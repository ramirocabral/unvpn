//! Anti-replay window shared by the OpenVPN and ESP data planes.

/// Sliding-window replay protection over the last 64 sequence numbers.
#[derive(Default)]
pub struct Replay {
    top: u32,
    bits: u64,
}

impl Replay {
    /// True if `id` is new (and records it); false for a replay / too-old packet.
    pub fn check(&mut self, id: u32) -> bool {
        if id == 0 {
            return false;
        }
        if id > self.top {
            let shift = id - self.top;
            self.bits = if shift >= 64 { 0 } else { self.bits << shift };
            self.bits |= 1;
            self.top = id;
            return true;
        }
        let back = self.top - id;
        if back >= 64 {
            return false;
        }
        let m = 1u64 << back;
        if self.bits & m != 0 {
            return false;
        }
        self.bits |= m;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window() {
        let mut r = Replay::default();
        assert!(r.check(1) && r.check(3) && r.check(2));
        assert!(!r.check(2) && !r.check(0));
        assert!(r.check(100));
        assert!(!r.check(30));
        assert!(r.check(99));
    }
}
