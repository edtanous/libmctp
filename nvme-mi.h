/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _NVMEMI_H
#define _NVMEMI_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdlib.h>

// NVM Express Management Interface 1.0 section 3.2.1
#define NVME_MI_MESSAGE_TYPE      0x04
#define MCTP_CONTROL_MESSAGE_TYPE 0x00

#define NVME_MI_MESSAGE_TYPE_MASK 0x7F

// Indicates this is covered by an MCTP integrity check
#define NVME_MI_MCTP_INTEGRITY_CHECK (1<<7)

// Indicates whether this is a request or response
#define NVME_MI_HDR_FLAG_ROR (1<<7)

#define NVME_MI_HDR_FLAG_MSG_TYPE_MASK 0x0F
#define NVME_MI_HDR_FLAG_MSG_TYPE_SHIFT (3)

enum NVME_MI_HDR_MESSAGE_TYPE {
        NVME_MI_HDR_MESSAGE_TYPE_CONTROL_PRIMITIVE         = 0x00,
        NVME_MI_HDR_MESSAGE_TYPE_MI_COMMAND                = 0x01,
        NVME_MI_HDR_MESSAGE_TYPE_MI_ADMIN_COMMAND          = 0x02,
        NVME_MI_HDR_MESSAGE_TYPE_PCIE_COMMAND              = 0x04,
};

enum NVME_MI_HDR_COMMAND_SLOT {
        NVME_MI_HDR_COMMAND_SLOT_0                         = 0x00,
        NVME_MI_HDR_COMMAND_SLOT_1                         = 0x01,
};

enum NVME_MI_HDR_STATUS {
        NVME_MI_HDR_STATUS_SUCCESS                         = 0x00,
        NVME_MI_HDR_STATUS_MORE_PROCESSING_REQUIRED        = 0x01,
        NVME_MI_HDR_STATUS_INTERNAL_ERROR                  = 0x02,
        NVME_MI_HDR_STATUS_INVALID_COMMAND_OPCODE          = 0x03,
        NVME_MI_HDR_STATUS_INVALID_PARAMETER               = 0x04,
        NVME_MI_HDR_STATUS_INVALID_COMMAND_SIZE            = 0x05,
        NVME_MI_HDR_STATUS_INVALID_COMMAND_INPUT_DATA_SIZE = 0x06,
        NVME_MI_HDR_STATUS_ACCESS_DENIED                   = 0x07,
        NVME_MI_HDR_STATUS_VPD_UPDATES_EXCEEDED            = 0x20,
        NVME_MI_HDR_STATUS_PCIE_INACCESSIBLE               = 0x21,
};

enum NVME_MI_OPCODE {
        NVME_MI_OPCODE_READ_MI_DATA                        = 0x00,
        NVME_MI_OPCODE_HEALTH_STATUS_POLL                  = 0x01,
        NVME_MI_OPCODE_CONTROLLER_HEALTH_STATUS_POLL       = 0x02,
        NVME_MI_OPCODE_CONFIGURATION_GET                   = 0x03,
        NVME_MI_OPCODE_CONFIGURATION_SET                   = 0x04,
        NVME_MI_OPCODE_VPD_READ                            = 0x05,
        NVME_MI_OPCODE_VPD_WRITE                           = 0x06,
        NVME_MI_OPCODE_RESET                               = 0x07,
};

#define NVME_MI_MSG_REQUEST_HEADER_SIZE 16
struct nvme_mi_msg_request_header {
        uint8_t message_type;
        uint8_t flags;
        uint8_t opcode;
        uint32_t dword0;
        uint32_t dword1;
};

struct nvme_mi_msg_request {
        struct nvme_mi_msg_request_header header;
        uint8_t request_data[128];
        size_t request_data_len;
};

#define NVME_MI_MSG_RESPONSE_HEADER_SIZE 5
struct nvme_mi_msg_response_header {
        uint8_t message_type;
        uint8_t flags;
        // Reserved bits 2:3
        uint8_t status;
};

struct nvme_mi_controller_health {
        uint8_t nvm_subsystem_status;
        uint8_t smart_warnings;
        uint8_t composite_temperature;
        uint8_t percent_used;
        uint16_t composite_controller_status;
};

#ifdef __cplusplus
}
#endif

#endif /* _NVMEMI_H */