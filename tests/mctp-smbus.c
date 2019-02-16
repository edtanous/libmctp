
#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "crc32c.h"
#include "libmctp-smbus.h"
#include "libmctp.h"

// NVM Express Management Interface 1.0 section 3.2.1
#define NVME_MI_MESSAGE_TYPE 0x04
// Indicates this is covered by an MCTP integrity check
#define NVME_MI_MCTP_INTEGRITY_CHECK (1 << 7)

#define NVME_MI_HDR_FLAG_ROR (1 << 7)
#define NVME_MI_HDR_FLAG_MSG_TYPE_MASK 0x0F
#define NVME_MI_HDR_FLAG_MSG_TYPE_SHIFT (3)

enum NVME_MI_HDR_MESSAGE_TYPE
{
    NVME_MI_HDR_MESSAGE_TYPE_CONTROL_PRIMITIVE = 0,
    NVME_MI_HDR_MESSAGE_TYPE_MI_COMMAND = 1,
    NVME_MI_HDR_MESSAGE_TYPE_MI_ADMIN_COMMAND = 2,
    NVME_MI_HDR_MESSAGE_TYPE_PCIE_COMMAND = 4,
};

enum NVME_MI_HDR_COMMAND_SLOT
{
    NVME_MI_HDR_COMMAND_SLOT_0 = 0,
    NVME_MI_HDR_COMMAND_SLOT_1 = 1,
};

enum NVME_MI_HDR_STATUS
{
    NVME_MI_HDR_STATUS_SUCCESS = 0x0,
    NVME_MI_HDR_STATUS_MORE_PROCESSING_REQUIRED = 0x1,
    NVME_MI_HDR_STATUS_INTERNAL_ERROR = 0x2,
    NVME_MI_HDR_STATUS_INVALID_COMMAND_OPCODE = 0x3,
    NVME_MI_HDR_STATUS_INVALID_PARAMETER = 0x4,
    NVME_MI_HDR_STATUS_INVALID_COMMAND_SIZE = 0x5,
    NVME_MI_HDR_STATUS_INVALID_COMMAND_INPUT_DATA_SIZE = 0x6,
    NVME_MI_HDR_STATUS_ACCESS_DENIED = 0x7,
    NVME_MI_HDR_STATUS_VPD_UPDATES_EXCEEDED = 0x20,
    NVME_MI_HDR_STATUS_PCIE_INACCESSIBLE = 0x20,
};

// TODO(ed) build a better "NVME-MI packet" type

struct nvme_mi_msg_request_header
{
    uint8_t message_type;
    uint8_t flags;
    uint16_t reserved;
}__attribute__((packed));


struct nvme_mi_msg_response_header
{
    uint8_t message_type;
    uint8_t flags;
    uint16_t reserved;
    uint8_t status;
}__attribute__((packed));


struct nvme_mi_msg_trailer
{
    uint32_t message_integrity_check;
};

struct nvme_mi_controller_health
{
    uint8_t unknown1;
    uint8_t unknown2;
    uint8_t unknown3;
    uint16_t controller_identifier;
    uint16_t controller_status;
    uint16_t temperature_kelvin;
    uint8_t percentage_used;
    uint8_t available_spare;
    uint8_t critical_warning;
}__attribute__((packed));

static void
    rx_message(uint8_t eid, void* data, void* msg, size_t len)
{
    struct nvme_mi_msg_response_header* header;
    struct nvme_mi_msg_trailer* trailer;
    struct nvme_mi_controller_health* health;
    uint8_t* message_data;
    size_t message_len;

    fprintf(stderr, "Got message from eid %d\n", eid);
    fprintf(stderr, "Got a message of length %zu\n", len);
    if (msg == NULL)
    {
        return;
    }

    fprintf(stderr, "\n");

    header = msg;
    fprintf(stderr, "message type %04X\n", header->message_type);
    fprintf(stderr, "nvme flags %02X\n", header->flags);
    fprintf(stderr, "reserved %02X\n", header->reserved);

    if (header->status != NVME_MI_HDR_STATUS_SUCCESS)
    {
        fprintf(stderr, "Command failed with status %02X\n", header->status);
        return;
    }

    message_data = msg + sizeof(*header);
    message_len = len - sizeof(*header) - sizeof(*trailer);
    trailer = (void*)((uint8_t*)msg + len - sizeof(*trailer));

    uint32_t integrity = crc32c((uint8_t*)msg, len - sizeof(*trailer));
    if (integrity != trailer->message_integrity_check)
    {
        fprintf(stderr, "CRC mismatch.  Got=%08X expected=%08X\n",
                trailer->message_integrity_check, trailer);
        return;
    }

    if (((header->flags >> NVME_MI_HDR_FLAG_MSG_TYPE_SHIFT) &
         NVME_MI_HDR_FLAG_MSG_TYPE_MASK) == NVME_MI_HDR_MESSAGE_TYPE_MI_COMMAND)
    {

        fprintf(stderr, "message_len=%d  sizeof=%d\n", message_len,
                sizeof(*health));
        if (message_len >= sizeof(*health))
        {
            health = (void*)message_data;
            fprintf(stderr, "Controller temperature %d kelvin\n",
                    health->temperature_kelvin);
            fprintf(stderr, "percentage used %d\n", health->percentage_used);
        }
    }

    fprintf(stderr, "Message length %d\n", message_len);
    for (size_t i = 0; i < message_len; i++)
    {
        fprintf(stderr, "%02X ", *((uint8_t*)message_data + i));
    }
    fprintf(stderr, "\n");
}

int main(void)
{
    struct mctp_binding_smbus* smbus;
    mctp_eid_t eid = 0;
    struct pollfd pollfds[3];
    int rc, n, mctp_fd;
    struct mctp* mctp;
    uint32_t integrity;

    struct nvme_mi_msg_request_header* header;
    struct nvme_mi_msg_trailer* trailer;

    mctp = mctp_init();

    assert(mctp);

    smbus = mctp_smbus_init();
    assert(smbus);

    mctp_smbus_open_path(smbus, "/dev/i2c-15",
                         "/sys/bus/i2c/devices/i2c-2/2-1010/slave-mqueue");

    mctp_smbus_register_bus(smbus, mctp, eid);

    mctp_set_rx_all(mctp, rx_message, NULL);

    pollfds[0].fd = mctp_smbus_get_in_fd(smbus);
    pollfds[0].events = POLLIN | POLLPRI;
    pollfds[1].fd = mctp_smbus_get_out_fd(smbus);
    pollfds[1].events = POLLIN;
    pollfds[2].fd = STDIN_FILENO;
    pollfds[2].events = POLLIN;
    n = 1;

    uint8_t vpd_read_256[] = {0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0xff, 0x00, 0x00, 0x00};
    uint8_t health_poll[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0xfe, 0x80, 0x1f, 0x00, 0x00, 0x00};

    uint8_t message[sizeof(health_poll) + sizeof(*header) + sizeof(*trailer)];

    header = (void*)message;
    header->message_type = NVME_MI_MESSAGE_TYPE | NVME_MI_MCTP_INTEGRITY_CHECK;
    header->flags = (NVME_MI_HDR_MESSAGE_TYPE_MI_COMMAND
                     << NVME_MI_HDR_FLAG_MSG_TYPE_SHIFT) |
                    NVME_MI_HDR_COMMAND_SLOT_0;
    header->reserved = 0;
    // TODO(ed) range checks
    memcpy(message + sizeof(*header), health_poll, sizeof(health_poll));

    trailer = (void*)message + sizeof(message) - sizeof(*trailer);
    trailer->message_integrity_check =
        crc32c(message, sizeof(message) - sizeof(*trailer));

    fprintf(stderr, "Message length %d\n", sizeof(message));
    for (size_t i = 0; i < sizeof(message); i++)
    {
        fprintf(stderr, "%02X ", message[i]);
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "integrity=%04X\n", trailer->message_integrity_check);

    mctp_message_tx(mctp, eid, message, sizeof(message));

    uint8_t buf[1024];

    for (;;)
    {
        rc = poll(pollfds, n, -1);
        //err(EXIT_FAILURE, "Poll returned");
        if (rc < 0)
            return EXIT_FAILURE;

        if (pollfds[0].revents)
        {
            fprintf(stderr, "i2c in event\n");
            rc = mctp_smbus_read(smbus);
            if (rc)
                pollfds[0].fd = -1;
        }

        if (pollfds[1].revents)
        {
            fprintf(stderr, "i2c out event\n");
            // rc = mctp_smbus_read(smbus);
            if (rc)
                pollfds[1].fd = -1;
        }

        if (n > 2 && pollfds[2].revents)
        {
            rc = read(STDIN_FILENO, buf, sizeof(buf));
            if (rc == 0)
            {
                n = 2;
                close(mctp_fd);
                pollfds[0].fd = -1;
            }
            else if (rc < 0)
            {
                err(EXIT_FAILURE, "read");
            }
            else
            {
            }
        }

        if (n == 2 && pollfds[0].fd < 0 && pollfds[1].fd < 0)
            break;
    }

    return EXIT_SUCCESS;
}
