import socket
import struct
import re
import time
import getpass

# ============================================================
#                     ORIGINAL SETTINGS
# ============================================================

LOGIN_SERVER_IP = "54.93.167.80"
STATIC_IGG_ID = 636676546
STATIC_ACCESS_KEY = "8014f08a46416574f355dcacc06dea1a"
LOGIN_SERVER_PORT = 5995
GAME_SERVER_PORT = 7001
RECONNECT_DELAY_SECONDS = 1

CMSG_LOGIN = 0x000B
CMSG_LOGIN_RETURN = 0x000C
CMSG_ENTER_GAME_REQUEST = 0x001F
CMSG_ENTER_GAME_RETURN = 0x0020
# Captures of the older game server returned 0x01; the current endpoint has
# returned 0x02. The latter is recognized for continued observation, but is
# not treated as proof that the castle has loaded.
ENTER_GAME_CONTINUE_STATUSES = {0x01, 0x02}

CMSG_EXTRA_ATTRIBUTE_INFO = 0x0021

MSG_0042 = 0x0042
MSG_0043 = 0x0043
MSG_026D = 0x026D
MSG_036C = 0x036C
MSG_06AB = 0x06AB
MSG_0037 = 0x0037
MSG_0033 = 0x0033

PLATFORM = 2
LOGIN_SERVER_ID = 8
GAME_INFO_4 = 0x3F00FF0E
CRYPT_KEY = b"CQ_secret"


# ============================================================
#                     ACCESS KEY ENCRYPTION
# ============================================================

def encrypt_access_key(access_key):
    data = access_key.encode("ascii")

    return bytes(
        value ^ CRYPT_KEY[i % len(CRYPT_KEY)]
        for i, value in enumerate(data)
    )


# ============================================================
#                     SOCKET FUNCTIONS
# ============================================================

def recv_exact(sock, size):
    data = b""

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Connection closed by server")

        data += chunk

    return data


def recv_packet(sock):
    header = recv_exact(sock, 4)

    length, opcode = struct.unpack("<HH", header)

    if length < 4:
        raise ValueError(
            f"Invalid packet length: {length}; "
            f"header bytes: {header.hex(' ')}"
        )

    body = recv_exact(sock, length - 4)

    return length, opcode, body


# ============================================================
#                     PACKET BUILDER
# ============================================================

def build_packet(opcode, body=b""):
    packet_length = 4 + len(body)

    return (
        struct.pack("<HH", packet_length, opcode)
        + body
    )


# ============================================================
#                     LOGIN PACKET
# ============================================================

def build_login_packet(igg_id, encrypted_key):

    body = struct.pack(
        "<IIQ",
        1,
        0,
        igg_id
    )

    body += struct.pack(
        "<H",
        len(encrypted_key)
    )

    body += encrypted_key

    body += struct.pack(
        "<IIIIII B",
        0,
        PLATFORM,
        0,
        LOGIN_SERVER_ID,
        GAME_INFO_4,
        0,
        1
    )

    return build_packet(
        CMSG_LOGIN,
        body
    )


# ============================================================
#                     LOGIN RESPONSE
# ============================================================

def parse_login_return(packet):

    packet_length, opcode = struct.unpack(
        "<HH",
        packet[:4]
    )

    if opcode != CMSG_LOGIN_RETURN:
        raise ValueError(
            f"Unexpected opcode: 0x{opcode:04X}"
        )

    body = packet[4:]

    offset = 0

    returned_igg_id = struct.unpack_from(
        "<Q",
        body,
        offset
    )[0]

    offset += 8

    ip_length = struct.unpack_from(
        "<H",
        body,
        offset
    )[0]

    offset += 2

    game_server_ip = body[
        offset:offset + ip_length
    ].decode(
        "ascii",
        errors="replace"
    )

    offset += ip_length

    unknown_2 = body[
        offset:offset + 2
    ]

    offset += 2

    session_length = struct.unpack_from(
        "<H",
        body,
        offset
    )[0]

    offset += 2

    session_value = body[
        offset:offset + session_length
    ]

    offset += session_length

    remaining = body[offset:]

    return {
        "igg_id": returned_igg_id,
        "game_server_ip": game_server_ip,
        "unknown_2": unknown_2,
        "session_value": session_value,
        "remaining": remaining
    }


# ============================================================
#                     ENTER GAME PACKET
# ============================================================

def build_enter_game_packet(
    igg_id,
    session_value
):

    if isinstance(session_value, str):
        session_value = session_value.encode("ascii")

    if len(session_value) != 32:
        raise ValueError(
            f"Session value must be 32 bytes, got {len(session_value)}"
        )

    body = struct.pack(
        "<IIQ",
        1,
        0,
        igg_id
    )

    body += struct.pack(
        "<H",
        len(session_value)
    )

    body += session_value

    body += bytes.fromhex(
        "0e 0e ff 00 3f 00 00 00 00 00"
    )

    return build_packet(
        CMSG_ENTER_GAME_REQUEST,
        body
    )


# ============================================================
#                     0x0021
# ============================================================

def build_extra_attribute_info(igg_id):

    body = struct.pack(
        "<Q",
        igg_id
    )

    body += bytes.fromhex(
        "0e 0e ff 00 3f f0 9e 5c 00"
    )

    packet = build_packet(
        CMSG_EXTRA_ATTRIBUTE_INFO,
        body
    )

    if len(packet) != 21:
        raise ValueError(
            f"0x0021 packet is {len(packet)} bytes"
        )

    return packet


# ============================================================
#                     0x0042
# ============================================================

def build_0042(body):

    if len(body) != 8:
        raise ValueError(
            "0x0042 body must be exactly 8 bytes"
        )

    return build_packet(
        MSG_0042,
        body
    )


# Values observed in the supplied PCAP.
#
# IMPORTANT:
# These are kept exactly as captured.
# They are NOT assumed to be a general algorithm.
# ============================================================

PCAP_0042_SEQUENCE = [

    bytes.fromhex(
        "fd 8a 00 00 00 00 00 00"
    ),

    bytes.fromhex(
        "b5 c5 00 00 00 00 00 00"
    ),

    bytes.fromhex(
        "71 00 01 00 00 00 00 00"
    ),

    bytes.fromhex(
        "19 3b 01 00 00 00 00 00"
    )
]


# ============================================================
#                     0x0043
# ============================================================

def build_0043():

    body = bytes(16)

    return build_packet(
        MSG_0043,
        body
    )


# ============================================================
#                     0x06AB
# ============================================================

def build_06ab():

    return build_packet(
        MSG_06AB,
        b""
    )


# ============================================================
#                     SEND CLIENT PACKET
# ============================================================

def send_client_packet(
    sock,
    opcode,
    body=b""
):

    packet = build_packet(
        opcode,
        body
    )

    sock.sendall(packet)

    print()
    print("=" * 78)
    print("[>>> CLIENT -> SERVER]")
    print("=" * 78)

    print(f"Length : {len(packet)}")
    print(f"Opcode : 0x{opcode:04X}")
    print(f"Body   : {body.hex(' ')}")
    print(f"HEX    : {packet.hex(' ')}")

    print("=" * 78)

    return packet


# ============================================================
#                     ARABIC EXTRACTION
# ============================================================

def extract_arabic_text(data):

    arabic = (
        "\u0600-\u06FF"
        "\u0750-\u077F"
        "\u08A0-\u08FF"
    )

    results = []

    current = bytearray()

    def flush():

        nonlocal current

        if not current:
            return

        try:
            text_part = bytes(
                current
            ).decode(
                "utf-8",
                errors="strict"
            )

        except UnicodeDecodeError:

            current.clear()
            return

        current.clear()

        if re.search(
            f"[{arabic}]",
            text_part
        ):

            text_part = text_part.strip(
                "\x00\r\n\t "
            )

            if text_part:
                results.append(
                    text_part
                )

    i = 0

    while i < len(data):

        byte = data[i]

        if byte < 0x80:

            current.append(byte)
            i += 1
            continue

        if 0xC2 <= byte <= 0xDF:
            char_len = 2

        elif 0xE0 <= byte <= 0xEF:
            char_len = 3

        elif 0xF0 <= byte <= 0xF4:
            char_len = 4

        else:

            flush()
            i += 1
            continue

        if i + char_len > len(data):

            flush()
            break

        raw_char = data[
            i:i + char_len
        ]

        if not all(
            0x80 <= value <= 0xBF
            for value in raw_char[1:]
        ):

            flush()
            i += 1
            continue

        try:

            char = raw_char.decode(
                "utf-8",
                errors="strict"
            )

        except UnicodeDecodeError:

            flush()
            i += 1
            continue

        if len(char) != 1:

            flush()
            i += 1
            continue

        current.extend(
            raw_char
        )

        i += char_len

    flush()

    unique = []
    seen = set()

    for item in results:

        if item not in seen:

            seen.add(item)
            unique.append(item)

    return unique


# ============================================================
#                     0x026D DISPLAY
# ============================================================

def show_026d_message(body):

    messages = extract_arabic_text(
        body
    )

    print()
    print("=" * 78)
    print("[<<< SERVER -> CLIENT] 0x026D")
    print("=" * 78)

    if messages:

        for message in messages:
            print(message)

    else:

        print(
            "[0x026D] "
            "لم يتم العثور على نص عربي UTF-8."
        )

    print("=" * 78)


# ============================================================
#                     SERVER PACKET DISPLAY
# ============================================================

def show_server_packet(
    length,
    opcode,
    body
):

    packet = struct.pack(
        "<HH",
        length,
        opcode
    ) + body

    print()
    print("=" * 78)
    print("[<<< SERVER -> CLIENT]")
    print("=" * 78)

    print(f"Length : {length}")
    print(f"Opcode : 0x{opcode:04X}")
    print(f"Body   : {body.hex(' ')}")
    print(f"FULL   : {packet.hex(' ')}")

    print("=" * 78)


# ============================================================
#                     0x0042 STATE
# ============================================================

class GameState:

    def __init__(self):

        self.last_0042 = None

        self.next_0042_index = 0

    def send_next_0042(self, sock):

        if self.next_0042_index >= len(
            PCAP_0042_SEQUENCE
        ):

            print(
                "[*] No more captured 0x0042 "
                "values available."
            )

            return False

        body = PCAP_0042_SEQUENCE[
            self.next_0042_index
        ]

        self.next_0042_index += 1

        self.last_0042 = body

        send_client_packet(
            sock,
            MSG_0042,
            body
        )

        return True


# ============================================================
#                     PERSISTENT GAME SESSION
# ============================================================

def keep_game_session(
    game_sock,
    igg_id
):

    print()
    print("=" * 60)
    print("              PERSISTENT GAME SESSION")
    print("=" * 60)

    print()
    print("[*] Game connection is now persistent.")
    print("[*] Ctrl+C = manual logout.")
    print()

    state = GameState()

    # --------------------------------------------------------
    # 0x0021
    # --------------------------------------------------------

    packet_0021 = build_extra_attribute_info(
        igg_id
    )

    send_client_packet(
        game_sock,
        CMSG_EXTRA_ATTRIBUTE_INFO,
        packet_0021[4:]
    )

    # --------------------------------------------------------
    # FIRST 0x0042
    # --------------------------------------------------------

    first_0042 = PCAP_0042_SEQUENCE[0]

    state.next_0042_index = 1

    state.last_0042 = first_0042

    send_client_packet(
        game_sock,
        MSG_0042,
        first_0042
    )

    # --------------------------------------------------------
    # 0x0043
    # --------------------------------------------------------

    packet_0043 = build_0043()

    send_client_packet(
        game_sock,
        MSG_0043,
        packet_0043[4:]
    )

    # --------------------------------------------------------
    # RECEIVE LOOP
    # --------------------------------------------------------

    previous_timeout = game_sock.gettimeout()

    game_sock.settimeout(1.0)

    try:

        while True:

            try:

                length, opcode, body = recv_packet(
                    game_sock
                )

            except socket.timeout:

                continue

            # =================================================
            # 0x026D
            # =================================================

            if opcode == MSG_026D:

                show_026d_message(
                    body
                )

                continue

            # =================================================
            # 0x036C
            # =================================================

            if opcode == MSG_036C:

                show_server_packet(
                    length,
                    opcode,
                    body
                )

                print(
                    "[*] 0x036C received."
                )

                print(
                    "[*] No response."
                )

                continue

            # =================================================
            # 0x0042
            # =================================================

            if opcode == MSG_0042:

                show_server_packet(
                    length,
                    opcode,
                    body
                )

                print(
                    "[*] Server 0x0042 received."
                )

                # ------------------------------------------------
                # IMPORTANT:
                # DO NOT ECHO THE SAME SERVER PACKET.
                # Instead move to the next 0x0042 observed
                # in the supplied PCAP.
                # ------------------------------------------------

                if state.next_0042_index < len(
                    PCAP_0042_SEQUENCE
                ):

                    time.sleep(0.05)

                    state.send_next_0042(
                        game_sock
                    )

                else:

                    print(
                        "[*] No further captured "
                        "0x0042 values."
                    )

                continue

            # =================================================
            # 0x0043
            # =================================================

            if opcode == MSG_0043:

                show_server_packet(
                    length,
                    opcode,
                    body
                )

                print(
                    "[*] 0x0043 received."
                )

                print(
                    "[*] No automatic response."
                )

                continue

            # =================================================
            # 0x0037
            # =================================================

            if opcode == MSG_0037:

                show_server_packet(
                    length,
                    opcode,
                    body
                )

                print(
                    "[*] 0x0037 received."
                )

                continue

            # =================================================
            # 0x0033
            # =================================================

            if opcode == MSG_0033:

                show_server_packet(
                    length,
                    opcode,
                    body
                )

                print(
                    "[*] 0x0033 received."
                )

                continue

            # =================================================
            # OTHER SERVER PACKETS
            # =================================================

            show_server_packet(
                length,
                opcode,
                body
            )

    except KeyboardInterrupt:

        print()
        print(
            "[*] Manual logout requested."
        )

        return False

    finally:

        try:
            game_sock.settimeout(
                previous_timeout
            )

        except OSError:
            pass


# ============================================================
#                     LOGIN
# ============================================================

def login(
    igg_id,
    access_key
):

    encrypted_key = encrypt_access_key(
        access_key
    )

    print(
        "[+] AccessKey length:",
        len(access_key)
    )

    print(
        "[+] Encrypted AccessKey length:",
        len(encrypted_key)
    )

    print("[+] Encrypted AccessKey details omitted.")

    packet = build_login_packet(
        igg_id,
        encrypted_key
    )

    print(
        "[+] CMSG_LOGIN size:",
        len(packet),
        "bytes"
    )

    print(
        "[+] Opcode:",
        f"0x{CMSG_LOGIN:04X}"
    )

    print("[+] LOGIN packet bytes omitted (contain credential material).")

    sock = socket.create_connection(
        (
            LOGIN_SERVER_IP,
            LOGIN_SERVER_PORT
        ),
        timeout=10
    )

    try:

        print(
            f"[+] Connected to "
            f"{LOGIN_SERVER_IP}:{LOGIN_SERVER_PORT}"
        )

        sock.sendall(
            packet
        )

        print(
            "[+] CMSG_LOGIN sent"
        )

        header = recv_exact(
            sock,
            4
        )

        response_length, response_opcode = struct.unpack(
            "<HH",
            header
        )

        body = recv_exact(
            sock,
            response_length - 4
        )

        response = header + body

        print()
        print(
            "[<<< SERVER -> CLIENT]"
        )

        print(
            f"[+] Response length: "
            f"{response_length}"
        )

        print(
            f"[+] Response opcode: "
            f"0x{response_opcode:04X}"
        )

        print("[+] Response body length:", len(body), "bytes")

        if response_opcode != CMSG_LOGIN_RETURN:

            raise RuntimeError(
                "Unexpected login opcode "
                f"0x{response_opcode:04X}"
            )

        return parse_login_return(
            response
        )

    finally:

        sock.close()

        print(
            "[+] Login connection closed"
        )


# ============================================================
#                     ENTER GAME
# ============================================================

def enter_game(
    login_data
):

    igg_id = login_data[
        "igg_id"
    ]

    game_ip = login_data[
        "game_server_ip"
    ]

    session_value = login_data[
        "session_value"
    ]

    print()
    print("=" * 60)
    print("ENTER GAME")
    print("=" * 60)

    print(
        "[+] Game Server:",
        f"{game_ip}:{GAME_SERVER_PORT}"
    )

    print(
        "[+] IGG ID:",
        igg_id
    )

    print(
        "[+] Session value length:",
        len(session_value)
    )

    packet = build_enter_game_packet(
        igg_id,
        session_value
    )

    print(
        "[+] CMSG_ENTER_GAME_REQUEST size:",
        len(packet),
        "bytes"
    )

    print(
        "[+] Opcode:",
        f"0x{CMSG_ENTER_GAME_REQUEST:04X}"
    )

    print("[+] Packet bytes omitted (contain session material).")

    game_sock = socket.create_connection(
        (
            game_ip,
            GAME_SERVER_PORT
        ),
        timeout=10
    )

    try:

        print(
            "[+] Game TCP connection established"
        )

        game_sock.sendall(
            packet
        )

        print(
            "[+] CMSG_ENTER_GAME_REQUEST sent"
        )

        header = recv_exact(
            game_sock,
            4
        )

        response_length, response_opcode = struct.unpack(
            "<HH",
            header
        )

        if response_length < 4:
            raise ValueError(
                f"Invalid game response length: {response_length}"
            )

        body = recv_exact(
            game_sock,
            response_length - 4
        )

        print()
        print(
            "[<<< SERVER -> CLIENT]"
        )

        print(
            "[+] Game response"
        )

        print(
            f"    Length : "
            f"{response_length}"
        )

        print(
            f"    Opcode : "
            f"0x{response_opcode:04X}"
        )

        print(
            f"    Body   : "
            f"{body.hex(' ')}"
        )

        if response_opcode != CMSG_ENTER_GAME_RETURN:
            print(
                "[-] Unexpected game response; closing this attempt "
                "and retrying login."
            )
            return True

        if len(body) != 1:
            print(
                "[-] Unexpected 0x0020 response format: "
                f"expected one status byte, received {len(body)} bytes. "
                "Retrying login."
            )
            return True

        status = body[0]
        if status not in ENTER_GAME_CONTINUE_STATUSES:
            print(
                "[-] The server returned enter-game status "
                f"0x{status:02X}, which is not in the recognized status set "
                f"{sorted(ENTER_GAME_CONTINUE_STATUSES)}. "
                "Closing this attempt and retrying login."
            )
            return True

        if status == 0x01:
            print("[+] Status 0x01 matches the successful supplied captures.")
        else:
            print(
                "[!] Status 0x02 was observed from the current endpoint. "
                "Continuing for diagnosis; this does not confirm castle entry."
            )

        # In all supplied successful captures, the client waits about
        # 3.4-3.6 seconds after 0x0020 before sending the post-entry 0x0021.
        post_entry_delay = 3.5
        print(
            f"[*] Waiting {post_entry_delay:.1f}s before post-entry traffic "
            "(timing observed in successful captures)."
        )
        time.sleep(post_entry_delay)

        # =====================================================
        # KEEP CONNECTION OPEN
        # =====================================================

        keep_game_session(
            game_sock,
            igg_id
        )

        # keep_game_session returns normally when the user presses Ctrl+C.
        return False

    except ValueError as exc:

        print()
        print(
            f"[-] Invalid game packet/session framing: {exc}"
        )
        print(
            "[*] Closing this session and retrying login."
        )

        return True

    except (
        ConnectionError,
        OSError
    ) as exc:

        print()
        print(
            f"[-] Game connection closed: "
            f"{exc}"
        )

        # Signal main() to log in again after a server-side disconnect.
        return True

    finally:

        try:

            game_sock.shutdown(
                socket.SHUT_RDWR
            )

        except OSError:
            pass

        game_sock.close()

        print(
            "[+] Game connection closed"
        )


# ============================================================
#                     MAIN
# ============================================================

def main():

    print("=" * 60)
    print("              GAME LOGIN CLIENT")
    print("=" * 60)

    igg_id = STATIC_IGG_ID
    access_key = STATIC_ACCESS_KEY

    if not access_key:

        print(
            "[-] AccessKey is empty"
        )

        return

    attempt = 0
    next_retry_at = 0.0

    while True:
        try:
            login_data = login(
                igg_id,
                access_key
            )

            print()
            print("[+] Login response received")
            print("[+] Returned IGG ID:", login_data["igg_id"])
            print("[+] Game Server IP:", login_data["game_server_ip"])

            disconnected = enter_game(login_data)
            if not disconnected:
                print("[*] Client stopped; no reconnect is needed.")
                return

        except Exception as exc:
            print(f"[-] Login/session attempt failed: {exc}")

        attempt += 1
        delay = max(0.0, next_retry_at - time.monotonic())
        if delay > 0:
            print(
                f"[*] Re-login attempt {attempt} in {delay:.1f}s "
                "(press Ctrl+C to stop)."
            )
            time.sleep(delay)
        else:
            print(
                f"[*] Re-login attempt {attempt} now "
                "(press Ctrl+C to stop)."
            )

        # A stable session can reconnect immediately after a later drop.
        # Only rapid repeated failures are rate-limited to avoid a tight loop.
        next_retry_at = time.monotonic() + RECONNECT_DELAY_SECONDS

#                     PROGRAM START
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print()
        print(
            "[!] Stopped by user"
        )

    except Exception as e:

        print()
        print(
            f"[!] Fatal error: {e}"
        )
