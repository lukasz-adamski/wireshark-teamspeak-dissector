--
-- TeamSpeak Protocol Dissector for Wireshark
--
--  Author: Łukasz "Adams" Adamski <lukasz.adamski@pm.me>
--  GitHub: https://github.com/lukasz-adamski/wireshark-teamspeak-dissector
--

teamspeak_proto = Proto("TeamSpeak", "TeamSpeak Protocol")

PACKET_TYPE_VOICE = 0x00
PACKET_TYPE_VOICE_WHISPER = 0x01
PACKET_TYPE_COMMAND = 0x02
PACKET_TYPE_COMMAND_LOW = 0x03
PACKET_TYPE_PING = 0x04
PACKET_TYPE_PONG = 0x05
PACKET_TYPE_ACK = 0x06
PACKET_TYPE_ACK_LOW = 0x07
PACKET_TYPE_INIT1 = 0x08

PACKET_FLAG_FRAGMENTED = 0x10
PACKET_FLAG_NEW_PROTOCOL = 0x20
PACKET_FLAG_COMPRESSED = 0x40
PACKET_FLAG_UNENCRYPTED = 0x80

PACKET_LEN_MAC = 8
PACKET_LEN_PACKET_ID = 2
PACKET_LEN_CLIENT_ID = 2
PACKET_LEN_FLAGS = 1
PACKET_LEN_TYPE = 1

PACKET_LEN_HEADER = PACKET_LEN_MAC + PACKET_LEN_PACKET_ID +
    PACKET_LEN_CLIENT_ID + PACKET_LEN_FLAGS + PACKET_LEN_TYPE

PACKET_PAYLOAD_CLIENT_OFFSET = PACKET_LEN_HEADER - 1 
PACKET_PAYLOAD_SERVER_OFFSET = PACKET_PAYLOAD_CLIENT_OFFSET - PACKET_LEN_CLIENT_ID

fields = {
    mac = ProtoField.new("Message Authentication Code", "teamspeak.mac", ftypes.BYTES),
    packet_id = ProtoField.new("Packet ID", "teamspeak.packet_id", ftypes.UINT16),
    client_id = ProtoField.new("Client ID", "teamspeak.client_id", ftypes.UINT16),
    flags = ProtoField.new("Flags", "teamspeak.flags", ftypes.UINT8),
    type = ProtoField.new("Type", "teamspeak.type", ftypes.UINT8),
    payload = ProtoField.new("Payload", "teamspeak.payload", ftypes.BYTES),

    init_sequence = ProtoField.new("Init sequence #", "teamspeak.init_sequence", ftypes.UINT8),
    init_client_version_timestamp = ProtoField.new("Client version timestamp", "teamspeak.version_timestamp", ftypes.STRING),
    init_current_timestamp = ProtoField.new("Current timestamp", "teamspeak.current_timestamp", ftypes.STRING),
    init_client_random_bytes = ProtoField.new("Random bytes", "teamspeak.client_random_bytes", ftypes.BYTES),
    init_server_bytes = ProtoField.new("Server bytes", "teamspeak.server_bytes", ftypes.BYTES),

    init_base = ProtoField.new("Base (BigInteger)", "teamspeak.init_base", ftypes.BYTES),
    init_modulo = ProtoField.new("Modulo (BigInteger)", "teamspeak.init_modulo", ftypes.BYTES),
    init_level = ProtoField.new("Level", "teamspeak.init_security_level", ftypes.UINT32),
    init_result = ProtoField.new("Result (BigInteger)", "teamspeak.init_result", ftypes.BYTES),
    init_command = ProtoField.new("Command", "teamspeak.init_command", ftypes.STRING)
}

teamspeak_proto.fields = fields

function dissect_ts3init1(tree, buffer, server)
    local offset = server and PACKET_PAYLOAD_SERVER_OFFSET or PACKET_PAYLOAD_CLIENT_OFFSET
    local sequence = server and buffer(offset, 1) or buffer(offset + 4, 1)

    tree:add(fields.init_sequence, sequence)
    sequence = sequence:uint()

    if (server == false) then
        local version_timestamp = buffer(offset, 4)
        tree:add(fields.init_client_version_timestamp, version_timestamp, version_timestamp:uint() .. " (" .. os.date("%x %X", version_timestamp:uint()) .. ")")
        
        if (sequence == 0) then
            local current_timestamp = buffer(offset + 5, 4)
            tree:add(fields.init_current_timestamp, current_timestamp, current_timestamp:uint() .. " (" .. os.date("%x %X", current_timestamp:uint()) .. ")")
            tree:add(fields.init_client_random_bytes, buffer(offset + 9, 4))
        end

        if (sequence == 2) then
            tree:add(fields.init_server_bytes, buffer(offset + 5, 16))

            -- TODO: REVERSED
            local random_bytes = buffer(offset + 21, 4)
            tree:add(fields.init_client_random_bytes, random_bytes)
        end

        if (sequence == 4) then
            tree:add(fields.init_base, buffer(offset + 5, 64))
            tree:add(fields.init_modulo, buffer(offset + 69, 64))
            tree:add(fields.init_level, buffer(offset + 133, 4))
            tree:add(fields.init_server_bytes, buffer(offset + 137, 100))
            tree:add(fields.init_result, buffer(offset + 237, 64))
            tree:add(fields.init_command, buffer(offset + 301))
        end
    else
        if (sequence == 1) then
            tree:add(fields.init_server_bytes, buffer(offset + 1, 16))

            -- TODO: REVERSED
            local random_bytes = buffer(offset + 17, 4)
            tree:add(fields.init_client_random_bytes, random_bytes)
        end

        if (sequence == 3) then
            tree:add(fields.init_base, buffer(offset + 1, 64))
            tree:add(fields.init_modulo, buffer(offset + 65, 64))
            tree:add(fields.init_level, buffer(offset + 129, 4))
            tree:add(fields.init_server_bytes, buffer(offset + 133, 100))
        end
    end

    return sequence
end

function check_bitwise_flag(flags, flag)
    return bit.band(flags, flag) ~= 0 and true or false
end

function process_flags(flags, flagstree)
    local flag_names = {}

    if (check_bitwise_flag(flags, PACKET_FLAG_FRAGMENTED)) then
        table.insert(flag_names, "FRAGMENTED")
        flagstree:add("1...", "Fragmented:", "Set")
    else
        flagstree:add("0...", "Fragmented:", "Not set")
    end

    if (check_bitwise_flag(flags, PACKET_FLAG_NEW_PROTOCOL)) then
        table.insert(flag_names, "NEW_PROTOCOL")
        flagstree:add(".1..", "New protocol:", "Set")
    else
        flagstree:add(".0..", "New protocol:", "Not set")
    end

    if (check_bitwise_flag(flags, PACKET_FLAG_COMPRESSED)) then
        table.insert(flag_names, "COMPRESSED")
        flagstree:add("..1.", "Compressed:", "Set")
    else
        flagstree:add("..0.", "Compressed:", "Not set")
    end

    if (check_bitwise_flag(flags, PACKET_FLAG_UNENCRYPTED)) then
        table.insert(flag_names, "UNENCRYPTED")
        flagstree:add("...1", "Unencrypted:", "Set")
    else
        flagstree:add("...0", "Unencrypted:", "Not set")
    end

    flagstree:append_text(" (" .. table.concat(flag_names, " ") .. ")")
end

function teamspeak_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end

    local server = (pinfo.match ~= pinfo.dst_port)

    local subtree = tree:add(teamspeak_proto, buffer(), "TeamSpeak Protocol Data")

    subtree:add(fields.mac, buffer(0, PACKET_LEN_MAC))
    subtree:add(fields.packet_id, buffer(8, PACKET_LEN_PACKET_ID))

    offset = 10
    if (server ~= true) then
        subtree:add(fields.client_id, buffer(offset, PACKET_LEN_CLIENT_ID))
        offset = 12
    end

    local byte = buffer(offset, PACKET_LEN_FLAGS):uint()
    local flags = bit.rshift(bit.band(byte, 0xF0), 4)
    local type = bit.band(byte, 0x0F)

    flagstree = subtree:add(fields.flags, flags)
    process_flags(byte, flagstree)

    local type_name = ({
        "VOICE",
        "VOICE_WHISPER",
        "COMMAND",
        "COMMAND_LOW",
        "PING",
        "PONG",
        "ACK",
        "ACK_LOW",
        "INIT1"
    })[type + 1]
    typetree = subtree:add(fields.type, type)
    typetree:append_text(" (" .. type_name .. ")")

    local protocol = teamspeak_proto.name .. " " 
        .. (server and "SERVER" or "CLIENT") .. " "
        .. type_name

    if (type == PACKET_TYPE_INIT1) then
        local sequence_number = dissect_ts3init1(subtree, buffer, server)

        protocol = protocol .. " #" .. sequence_number
    else
        subtree:add(fields.payload, buffer(
            server and PACKET_PAYLOAD_SERVER_OFFSET or PACKET_PAYLOAD_CLIENT_OFFSET
        ))
    end

    pinfo.cols.protocol = protocol
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(9987, teamspeak_proto)