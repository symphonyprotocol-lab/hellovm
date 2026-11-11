//! Memory syscalls: thin wrappers around [`crate::mm::Mm`].

use crate::errno::{Errno, SysResult, EINVAL, ENOMEM};
use crate::host::Host;
use crate::mm::{Mm, MAP_ANONYMOUS};
use crate::platform::{GuestAddr, Platform};

use super::Ctx;

impl<H: Host + ?Sized, P: Platform + ?Sized> Ctx<'_, H, P> {
    fn mm(&mut self) -> SysResult<&mut Mm> {
        self.proc.mm.as_mut().ok_or(Errno(ENOMEM))
    }

    pub fn sys_brk(&mut self, addr: GuestAddr) -> SysResult<u64> {
        let mm = self.proc.mm.as_mut().ok_or(Errno(ENOMEM))?;
        Ok(mm.brk(self.app, addr))
    }

    pub fn sys_mmap(&mut self, addr: GuestAddr, len: u64, prot: u64, flags: u64, fd: i64, offset: u64) -> SysResult<u64> {
        let contents = if flags & MAP_ANONYMOUS == 0 {
            let page = self.mm()?.page_size();
            if offset % page != 0 {
                return Err(Errno(EINVAL));
            }
            Some(self.mapping_contents(fd, offset, len)?)
        } else {
            None
        };
        let mm = self.proc.mm.as_mut().ok_or(Errno(ENOMEM))?;
        mm.mmap(self.app, addr, len, prot, flags, contents.as_deref())
    }

    pub fn sys_munmap(&mut self, addr: GuestAddr, len: u64) -> SysResult<u64> {
        let mm = self.proc.mm.as_mut().ok_or(Errno(ENOMEM))?;
        mm.munmap(self.app, addr, len).map(|()| 0)
    }

    pub fn sys_mprotect(&mut self, addr: GuestAddr, len: u64, prot: u64) -> SysResult<u64> {
        let mm = self.proc.mm.as_mut().ok_or(Errno(ENOMEM))?;
        mm.mprotect(self.app, addr, len, prot).map(|()| 0)
    }

    pub fn sys_mremap(&mut self, old: GuestAddr, old_len: u64, new_len: u64, flags: u64, new_addr: GuestAddr) -> SysResult<u64> {
        let mm = self.proc.mm.as_mut().ok_or(Errno(ENOMEM))?;
        mm.mremap(self.app, old, old_len, new_len, flags, new_addr)
    }
}
