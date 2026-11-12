//! Memory syscalls: thin wrappers around [`crate::mm::Mm`], applied to the
//! address space of the calling thread's process.

use crate::errno::{Errno, SysResult, EINVAL, ENOMEM};
use crate::host::Host;
use crate::mm::{Mm, MAP_ANONYMOUS};
use crate::platform::{GuestAddr, Platform, TaskMem};

use super::Ctx;

impl<H: Host + ?Sized, P: Platform + ?Sized> Ctx<'_, H, P> {
    /// The address space and a handle to change it.
    fn mm_and_space(&mut self) -> SysResult<(&mut Mm, TaskMem<'_, P>)> {
        let id = self.proc().mm.ok_or(Errno(ENOMEM))?;
        let mm = &mut self.st.mms.get_mut(id).mm;
        Ok((mm, TaskMem::new(self.plat, self.task)))
    }

    pub fn sys_brk(&mut self, addr: GuestAddr) -> SysResult<u64> {
        let (mm, mut space) = self.mm_and_space()?;
        Ok(mm.brk(&mut space, addr))
    }

    pub fn sys_mmap(
        &mut self,
        addr: GuestAddr,
        len: u64,
        prot: u64,
        flags: u64,
        fd: i64,
        offset: u64,
    ) -> SysResult<u64> {
        let contents = if flags & MAP_ANONYMOUS == 0 {
            let (mm, _) = self.mm_and_space()?;
            if !offset.is_multiple_of(mm.page_size()) {
                return Err(Errno(EINVAL));
            }
            Some(self.mapping_contents(fd, offset, len, flags)?)
        } else {
            None
        };
        let (mm, mut space) = self.mm_and_space()?;
        mm.mmap(&mut space, addr, len, prot, flags, contents.as_deref())
    }

    pub fn sys_munmap(&mut self, addr: GuestAddr, len: u64) -> SysResult<u64> {
        let (mm, mut space) = self.mm_and_space()?;
        mm.munmap(&mut space, addr, len).map(|()| 0)
    }

    pub fn sys_mprotect(&mut self, addr: GuestAddr, len: u64, prot: u64) -> SysResult<u64> {
        let (mm, mut space) = self.mm_and_space()?;
        mm.mprotect(&mut space, addr, len, prot).map(|()| 0)
    }

    pub fn sys_mremap(
        &mut self,
        old: GuestAddr,
        old_len: u64,
        new_len: u64,
        flags: u64,
        new_addr: GuestAddr,
    ) -> SysResult<u64> {
        let (mm, mut space) = self.mm_and_space()?;
        mm.mremap(&mut space, old, old_len, new_len, flags, new_addr)
    }
}
