# O-RAN SC i-release RIC + KPIMON-GO xApp simulator


from scapy.all import rdpcap, raw
from scapy.layers.sctp import SCTP, SCTPChunkData
import time, socket
import sctp
import threading



def send_subscription_request(client):
    time.sleep(10)

    print("Sending E2subscriptionRequest")
    client.sctp_send(e2_sub_req_chunk_data_payload)



def handle_client(client):

    data = client.recv(2048)
    pkt = SCTP() / data

    payload_len = len(raw(pkt.payload))

    if payload_len == 1533:
        print("Received E2setupRequest")
        print("Sending E2setupResponse")
        client.sctp_send(e2_setup_response_chunk_data_payload)

        sub_req_thread = threading.Thread(target=send_subscription_request, args=(client,))
        sub_req_thread.start()

    elif payload_len == 48:
        print(f"Received E2Indication: {data}")
    else:
        print(f"Received pkt of len={payload_len}")

def run_server():
    s = sctp.sctpsocket_tcp(socket.AF_INET)
    s.bind((server_ip, server_port))
    s.listen()

    client, addr = s.accept()
    while True:
        # print()
        # print("Call from {0}:{1}".format(addr[0], addr[1]))
        handle_client(client)



if __name__ == '__main__':
    server_ip = "172.27.7.15"
    server_port = 32222
    #dst_ip = "172.27.7.15"


    pkts = rdpcap("e2sm-working-i-release.pcapng")
    e2_setup_response = pkts[8]
    e2_setup_response_sctp = e2_setup_response.getlayer(SCTP)
    e2_setup_response_chunk_data = e2_setup_response.getlayer(SCTPChunkData)
    e2_setup_response_chunk_data_payload = raw(e2_setup_response_chunk_data.data)

    pkts_subscription = rdpcap("last-test.pcapng")
    e2_sub_req = pkts_subscription[4]
    e2_sub_req_chunk_data = e2_sub_req.getlayer(SCTPChunkData)
    e2_sub_req_chunk_data_payload = raw(e2_sub_req_chunk_data.data)

    run_server()


