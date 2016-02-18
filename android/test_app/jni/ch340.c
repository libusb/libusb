//libusb+ch340 data transfer demo
//gcc usb.c `pkg-config libusb-1.0 --libs --cflags` -o usb
//File origin: https://gist.github.com/593141477/8d9ecad151dad351fbbb
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/select.h>
#include <termios.h>

#include <libusb.h>

#define EP_DATA_IN        (0x2|LIBUSB_ENDPOINT_IN)
#define EP_DATA_OUT       (0x2|LIBUSB_ENDPOINT_OUT)
#define CTRL_IN           (LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_ENDPOINT_IN)
#define CTRL_OUT          (LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_ENDPOINT_OUT)
#define DEFAULT_BAUD_RATE 9600

static struct libusb_device_handle *devh = NULL;
static struct libusb_transfer *recv_bulk_transfer = NULL;
uint8_t dtr = 0;
uint8_t rts = 0;
int do_exit = 256;
uint8_t recvbuf[1024];

void writeHandshakeByte(void) {
    if (libusb_control_transfer(devh, CTRL_OUT, 0xa4, ~((dtr ? 1 << 5 : 0) | (rts ? 1 << 6 : 0)), 0, NULL, 0, 1000) < 0) {
        fprintf(stderr, "Faild to set handshake byte\n");
    }
}

int setBaudRate(int baudRate){
    static int baud[] = {2400, 0xd901, 0x0038, 4800, 0x6402,
            0x001f, 9600, 0xb202, 0x0013, 19200, 0xd902, 0x000d, 38400,
            0x6403, 0x000a, 115200, 0xcc03, 0x0008};

    for (int i = 0; i < sizeof(baud)/sizeof(int) / 3; i++) {
        if (baud[i * 3] == baudRate) {
            int r = libusb_control_transfer(devh, CTRL_OUT, 0x9a, 0x1312, baud[i * 3 + 1], NULL, 0, 1000);
            if (r < 0) {
                fprintf(stderr, "failed control transfer 0x9a,0x1312\n");
                return r;
            }
            r = libusb_control_transfer(devh, CTRL_OUT, 0x9a, 0x0f2c, baud[i * 3 + 2], NULL, 0, 1000);
            if (r < 0) {
                fprintf(stderr, "failed control transfer 0x9a,0x0f2c\n");
                return r;
            }

            return 0;
        }
    }
    fprintf(stderr, "unsupported baudrate\n");
    return -1;
}

int init_ch34x()
{
    int r;

    r = libusb_control_transfer(devh, CTRL_OUT, 0xa1, 0, 0, NULL, 0, 1000);
    if (r < 0) {
        fprintf(stderr, "failed control transfer 0xa1\n");
        return r;
    }
    r = libusb_control_transfer(devh, CTRL_OUT, 0x9a, 0x2518, 0x0050, NULL, 0, 1000);
    if (r < 0) {
        fprintf(stderr, "failed control transfer 0x9a,0x2518\n");
        return r;
    }
    r = libusb_control_transfer(devh, CTRL_OUT, 0xa1, 0x501f, 0xd90a, NULL, 0, 1000);
    if (r < 0) {
        fprintf(stderr, "failed control transfer 0xa1,0x501f\n");
        return r;
    }

    setBaudRate(DEFAULT_BAUD_RATE);
    writeHandshakeByte();

    return r;
}

static void LIBUSB_CALL cb_img(struct libusb_transfer *transfer)
{
    if (transfer->status != LIBUSB_TRANSFER_COMPLETED) {
    	if( transfer->status != LIBUSB_TRANSFER_CANCELLED )
    		fprintf(stderr, "img transfer status %d?\n", transfer->status);
        do_exit = 0;
        libusb_free_transfer(transfer);
        return;
    }

    // printf("Data callback[");
    for (int i = 0; i < transfer->actual_length; ++i)
    {
        putchar(recvbuf[i]);
    }
    fflush(stdout);
    // printf("]\n");

    if (libusb_submit_transfer(transfer) < 0)
        do_exit = 0;
}

int send_to_uart(void)
{
    int r;
    unsigned char sendbuf[1024];
    if ((r = read(0, sendbuf, sizeof(sendbuf))) < 0) {
        return r;
    } else {
        int transferred, len = r;
        r = libusb_bulk_transfer(devh, EP_DATA_OUT, sendbuf, len, &transferred, 200);
        // printf("read[%d]transferred[%d]\n", len, transferred);
        if(r < 0){
            fprintf(stderr, "libusb_bulk_transfer error %d\n", r);
            return r;
        }
    }
    return r;
}

int send_data(void)
{
    int r;
    unsigned char sendbuf[256];
	int transferred, len = r;
    memset(sendbuf,'U',sizeof(sendbuf));
	r = libusb_bulk_transfer(devh, EP_DATA_OUT, sendbuf, len, &transferred, 200);
	if(r < 0){
		fprintf(stderr, "libusb_bulk_transfer error %d\n", r);
		return r;
	}
    return r;
}


int kbhit()
{
    struct timeval tv = { 0L, 0L };
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(0, &fds);
    return select(1, &fds, NULL, NULL, &tv);
}

int main(int argc, char **argv)
{
    int r = 1;

    r = libusb_init(NULL);
    if (r < 0) {
        fprintf(stderr, "failed to initialise libusb\n");
        exit(1);
    }

    devh = libusb_open_device_with_vid_pid(NULL, 0x1a86, 0x7523);
    if (devh == NULL) {
        fprintf(stderr, "Could not find/open device\n");
        r = 1;
        goto out;
    }

    r = libusb_claim_interface(devh, 0);
    if (r < 0) {
        fprintf(stderr, "usb_claim_interface error %d\n", r);
        goto out;
    }
    printf("claimed interface\n");

    r = init_ch34x();
    if (r < 0)
        goto out_release;

    if(argc > 1)
        setBaudRate(atoi(argv[1]));

    printf("initialized\n");

    recv_bulk_transfer = libusb_alloc_transfer(0);
    if (!recv_bulk_transfer){
        fprintf(stderr, "libusb_alloc_transfer error\n");
        goto out_release;
    }

    libusb_fill_bulk_transfer(recv_bulk_transfer, devh, EP_DATA_IN, recvbuf,
        sizeof(recvbuf), cb_img, NULL, 0);

    r = libusb_submit_transfer(recv_bulk_transfer);
    if (r < 0){
        fprintf(stderr, "libusb_submit_transfer error\n");
        libusb_free_transfer(recv_bulk_transfer);
        goto out_release;
    }

    send_data();

    struct timeval tv = { 0L, 0L };
    while ( do_exit-- > 0 &&
   		(r = libusb_handle_events_timeout(NULL, &tv)) >= 0) usleep(10000);

    printf("\ndone\n");

    libusb_cancel_transfer(recv_bulk_transfer);
    libusb_handle_events_timeout(NULL, &tv);

out_release:
    libusb_release_interface(devh, 0);
out:
    libusb_close(devh);
    libusb_exit(NULL);
    return r >= 0 ? r : -r;
}
