
#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "crc32c.h"
#include "libmctp-smbus.h"
#include "nvme-mi.h"
#include "libmctp.h"

#define TIMEOUT_MS 1000

struct nvme_mi_transaction_context {
        size_t request_type;
};

static void help(void)
{
        fprintf(
            stderr,
            "Usage: mctp-smbus I2CBUS [ROOTI2CBUS]\n"
            "  I2CBUS is an integer representing the bus number to connect to\n"
            "  ROOTI2CBUS is an integer representing the root bus device to "
            "receive from if different than primary bus number\n");
        exit(1);
}

static void print_drive_temp(uint8_t temp_byte)
{
    if(temp_byte <= 0x7E || temp_byte > 0xC5){
        fprintf(stderr,"Temperature %d Celsius\n", (int8_t)temp_byte);
    } else if (temp_byte == 0x7F){
        fprintf(stderr,"Temperature 127 Celsius or higher\n");
    } else if (temp_byte == 0x80){
        fprintf(stderr,"No temperature data available\n");
    } else if (temp_byte == 0x81){
        fprintf(stderr,"Temperature sensor failure\n");
    } else if (temp_byte == 0xC4){
        fprintf(stderr,"Temperature is -60 Celsius or lower\n");
    }
}

static int verify_integrity(uint8_t* msg, size_t len){
        uint32_t calc_integrity;
        uint32_t msg_integrity;

        if (len < NVME_MI_MSG_RESPONSE_HEADER_SIZE + sizeof(msg_integrity)) {
                fprintf(stderr,
                        "Not enough bytes for nvme header and trailer\n");
                return -1;
        }

        msg_integrity = msg[len - 4] + (msg[len - 3] << 8) +
                (msg[len - 2] << 16) +
                (msg[len - 1] << 24);

        calc_integrity = crc32c(msg, len - sizeof(msg_integrity));
        if (msg_integrity != calc_integrity) {
                fprintf(stderr, "CRC mismatch.  Got=%08X expected=%08X\n",
                        msg_integrity, calc_integrity);
                return -1;
        }
        return 0;
}

static void rx_message(uint8_t eid, void *data, void *msg, size_t len)
{
        struct nvme_mi_transaction_context *nv_ctx;
        struct nvme_mi_msg_response_header header;
        uint8_t *message_data;
        size_t message_len;

        int count;

        nv_ctx = (void *)data;

        int request_type = nv_ctx->request_type;

        if (msg == NULL) {
                fprintf(stderr, "Bad msg\n");
                return;
        }

        fprintf(stderr, "Got message from eid %d with length %d\n", eid, len);

        if (len < NVME_MI_MSG_RESPONSE_HEADER_SIZE + sizeof(uint32_t)) {
                fprintf(stderr,
                        "Not enough bytes for nvme header and trailer\n");
                return -1;
        }

        message_data = msg;
        if (verify_integrity(message_data, len) != 0){
                return -1;
        }

        header.message_type = message_data[0];
        header.flags = message_data[1];
        header.status = message_data[4];

        if (header.status == NVME_MI_HDR_STATUS_MORE_PROCESSING_REQUIRED) {
                return;
        }

        nv_ctx->request_type = 0;

        if (header.status != NVME_MI_HDR_STATUS_SUCCESS) {
                fprintf(stderr, "Command failed with status %02X\n",
                        header.status);
                return;
        }

        message_data += NVME_MI_MSG_RESPONSE_HEADER_SIZE;
        message_len =
            len - NVME_MI_MSG_RESPONSE_HEADER_SIZE - sizeof(uint32_t);

        if ((header.message_type & NVME_MI_MESSAGE_TYPE_MASK) !=
            NVME_MI_MESSAGE_TYPE) {
                fprintf(stderr, "got non-nvme type message_type=%d\n",
                        header.message_type);
                return;
        }

        if (((header.flags >> NVME_MI_HDR_FLAG_MSG_TYPE_SHIFT) &
             NVME_MI_HDR_FLAG_MSG_TYPE_MASK) ==
            NVME_MI_HDR_MESSAGE_TYPE_MI_COMMAND) {
                switch (request_type) {
                case NVME_MI_OPCODE_HEALTH_STATUS_POLL:
                        if (message_len < 8){
                        fprintf(stderr, "Got improperly sized health status poll\n");
                        break;
                        }
                        print_drive_temp(message_data[5]);
                        break;

                case NVME_MI_OPCODE_VPD_READ:
                        fprintf(stderr, "VPD read length %d\n", message_len);
                        for (size_t i = 0; i < message_len; i++) {
                                if ((i % 16) == 0){
                                        //fprintf(stderr, "\n%04X ", i);
                                        fprintf(stderr, "\n");
                                }
                                fprintf(stderr, "%02X ",
                                        *((uint8_t *)message_data + i));
                        }
                        fprintf(stderr, "\n");
                        break;

                default:
                        fprintf(stderr, "Unknown message type length %d\n",
                        message_len);
                        for (size_t i = 0; i < message_len; i++) {
                        fprintf(stderr, "%02X ",
                                *((uint8_t *)message_data + i));
                        }
                        fprintf(stderr, "\n");
                        break;
                }
        } else {
                fprintf(stderr, "Unknown message type length %d\n",
                        message_len);
                for (size_t i = 0; i < message_len; i++) {
                        fprintf(stderr, "%02X ",
                        *((uint8_t *)message_data + i));
                }
                fprintf(stderr, "\n");
        }
}

int nvme_message_tx(struct mctp *mctp, uint8_t eid,
                    struct nvme_mi_msg_request *req)
{
        uint8_t message_buf[256] = {0};
        size_t msg_size;
        uint32_t integrity;

        if (req == NULL) {
            fprintf(stderr, "Bad request\n");
            return -1;
        }

        req->header.flags |= NVME_MI_HDR_MESSAGE_TYPE_MI_COMMAND
                     << NVME_MI_HDR_FLAG_MSG_TYPE_SHIFT;
        req->header.message_type =
            NVME_MI_MESSAGE_TYPE | NVME_MI_MCTP_INTEGRITY_CHECK;

        msg_size = NVME_MI_MSG_REQUEST_HEADER_SIZE + req->request_data_len +
           sizeof(integrity);
        if (sizeof(message_buf) < msg_size)
                return EXIT_FAILURE;

        message_buf[0] = req->header.message_type;
        message_buf[1] = req->header.flags;
        // Reserved bits 2-3

        message_buf[4] = req->header.opcode;
        // reserved bits 5-7
        message_buf[8] = req->header.dword0 & 0xff;
        message_buf[9] = (req->header.dword0 >> 8) & 0xff;
        message_buf[10] = (req->header.dword0 >> 16) & 0xff;
        message_buf[11] = (req->header.dword0 >> 24) & 0xff;

        message_buf[12] = req->header.dword1 & 0xff;
        message_buf[13] = (req->header.dword1 >> 8) & 0xff;
        message_buf[14] = (req->header.dword1 >> 16) & 0xff;
        message_buf[15] = (req->header.dword1 >> 24) & 0xff;

        memcpy(message_buf + NVME_MI_MSG_REQUEST_HEADER_SIZE, req->request_data,
               req->request_data_len);
        msg_size = NVME_MI_MSG_REQUEST_HEADER_SIZE + req->request_data_len;
        integrity = crc32c(message_buf, NVME_MI_MSG_REQUEST_HEADER_SIZE +
                            req->request_data_len);
        message_buf[msg_size] = integrity & 0xff;
        message_buf[msg_size + 1] = (integrity >> 8) & 0xff;
        message_buf[msg_size + 2] = (integrity >> 16) & 0xff;
        message_buf[msg_size + 3] = (integrity >> 24) & 0xff;
        msg_size += sizeof(integrity);
        return mctp_message_tx(mctp, eid, message_buf, msg_size);
}

int lookup_i2c_bus(const char *i2cbus_arg)
{
        unsigned long i2cbus;
        char *end;

        i2cbus = strtoul(i2cbus_arg, &end, 0);
        if (*end || !*i2cbus_arg) {
                /* Not a number */
                return -1;
        }
        if (i2cbus > 0xFFFFF) {
                fprintf(stderr, "Error: I2C bus out of range!\n");
                return -2;
        }

        return i2cbus;
}

int main(int argc, char *argv[])
{
        int r;
        struct mctp_binding_smbus *smbus;
        mctp_eid_t eid = 0;
        struct pollfd pollfds[1];
        int rc, n, mctp_fd;
        struct mctp *mctp;
        uint32_t integrity;
        int bus_num;
        int root_bus_num;
        size_t msg_size;

        struct nvme_mi_transaction_context nv_ctx = {0};

        mctp = mctp_init();

        assert(mctp);

        smbus = mctp_smbus_init();
        assert(smbus);

        if (argc < 2 || argc > 3)
                help();

        bus_num = lookup_i2c_bus(argv[1]);

        if (argc > 2) {
                root_bus_num = lookup_i2c_bus(argv[2]);
        } else {
                root_bus_num = bus_num;
        }

        r = mctp_smbus_open_bus(smbus, bus_num, root_bus_num);
                if (r < 0) {
                        return EXIT_FAILURE;
        }

        mctp_smbus_register_bus(smbus, mctp, eid);

        r = mctp_set_rx_all(mctp, rx_message, (void *)&nv_ctx);
                if (r < 0) {
                        return EXIT_FAILURE;
        }

        pollfds[0].fd = mctp_smbus_get_in_fd(smbus);
        pollfds[0].events = POLLPRI;
        n = 1;

        struct nvme_mi_msg_request req = {0};

#if 0
        req.header.opcode = NVME_MI_OPCODE_VPD_READ;
        req.header.dword0 = 0;
        // read length 256
        req.header.dword1 = 256;
        nv_ctx.request_type = NVME_MI_OPCODE_VPD_READ;
#else

        req.header.opcode = NVME_MI_OPCODE_HEALTH_STATUS_POLL;
        req.header.dword0 = 0;
        req.header.dword1 = 0;
        nv_ctx.request_type = NVME_MI_OPCODE_HEALTH_STATUS_POLL;

#endif

        rc = nvme_message_tx(mctp, eid, &req);
        if (rc < 0)
                return EXIT_FAILURE;

        while (nv_ctx.request_type != 0) {
                rc = poll(pollfds, n, TIMEOUT_MS);
                if (rc == 0){
                        fprintf(stderr, "Request timed out\n");
                }
                if (rc <= 0)
                        return EXIT_FAILURE;

                if (pollfds[0].revents & POLLPRI) {
                        rc = mctp_smbus_read(smbus);
                        if (rc) {
                                fprintf(stderr, "bad read\n");
                                pollfds[0].fd = -1;
                        }
                }

                if (pollfds[0].fd < 0)
                        break;
        }

        return EXIT_SUCCESS;
}
