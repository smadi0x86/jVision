from uploader.cli import main

"""
Usage:
    jvisionclient.py <target> [options]

Options:
    --server <server>    jVision server host
    --port <port>        jVision server port
    --subnet <subnet>    Subnet label to attach to hosts
    --xml <xml>          Existing Nmap XML (skip running nmap)
    --timing <timing>    Nmap timing template (default T3)
    --top-ports <ports>  Limit to top ports for gentler scans
    --verify-ssl         Verify SSL certificate
    --plugin <plugin>    Scanner plugin to use

Examples:
    python3 jvisionclient.py <target>
    python3 jvisionclient.py <target> --server <server> --port <port> --subnet <subnet>
    python3 jvisionclient.py <target> --xml <xml>
"""


if __name__ == "__main__":
    main()
