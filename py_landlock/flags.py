from enum import IntFlag


class AccessFs(IntFlag):
    """
    Filesystem access rights for Landlock rules.

    These flags define what operations are permitted on files and directories.
    Combine flags with | operator for multiple permissions.
    """

    EXECUTE = 1 << 0  # V1 - Execute a file
    WRITE_FILE = 1 << 1  # V1 - Open file with write access
    READ_FILE = 1 << 2  # V1 - Open file with read access
    READ_DIR = 1 << 3  # V1 - Open/list directory contents
    REMOVE_DIR = 1 << 4  # V1 - Remove empty directory
    REMOVE_FILE = 1 << 5  # V1 - Unlink file
    MAKE_CHAR = 1 << 6  # V1 - Create character device
    MAKE_DIR = 1 << 7  # V1 - Create directory
    MAKE_REG = 1 << 8  # V1 - Create regular file
    MAKE_SOCK = 1 << 9  # V1 - Create UNIX domain socket
    MAKE_FIFO = 1 << 10  # V1 - Create named pipe (FIFO)
    MAKE_BLOCK = 1 << 11  # V1 - Create block device
    MAKE_SYM = 1 << 12  # V1 - Create symbolic link
    REFER = 1 << 13  # V2 - Link/rename file across directories
    TRUNCATE = 1 << 14  # V3 - Truncate file size
    IOCTL_DEV = 1 << 15  # V5 - ioctl on device files


class AccessNet(IntFlag):
    """
    Network access rights for Landlock rules.

    These flags control TCP socket operations. Only TCP is supported by Landlock;
    UDP, SCTP, and other protocols cannot be restricted.

    Requires ABI V4+ (Linux 6.7+).
    """

    BIND_TCP = 1 << 0  # V4 - Bind to a TCP port
    CONNECT_TCP = 1 << 1  # V4 - Connect to a TCP port


class Scope(IntFlag):
    """
    Scope restrictions for Landlock rules.

    These flags restrict IPC mechanisms to processes within the same Landlock domain.

    Requires ABI V6+ (Linux 6.12+).
    """

    ABSTRACT_UNIX_SOCKET = 1 << 0  # V6 - Restrict abstract UNIX socket connections
    SIGNAL = 1 << 1  # V6 - Restrict signal delivery
