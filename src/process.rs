//! Settings shared by the child processes ghaudit runs (git, osv-scanner).

/// Windows' `CREATE_NO_WINDOW` process creation flag.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Run a child without a console window on Windows. A GUI front end has no console, so
/// without this every git and osv-scanner run would flash one; a console parent loses
/// nothing, since ghaudit pipes or discards every child's input and output.
pub(crate) fn hide_window(cmd: &mut tokio::process::Command) -> &mut tokio::process::Command {
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

/// [`hide_window`] for a blocking [`std::process::Command`].
pub(crate) fn hide_window_std(cmd: &mut std::process::Command) -> &mut std::process::Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}
