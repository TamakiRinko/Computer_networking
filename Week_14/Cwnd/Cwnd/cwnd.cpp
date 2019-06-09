#include<iostream>
#include<fstream>
#include<string>
using namespace std;

string myip = "172.27.133.233";			//����IP��ַ
string Seq = "Seq";
string Ack = "Ack";
string Syn = "[SYN]";
string Len = "Len";

int main(){
	ifstream fin;
	ofstream fout;
	fout.open("result", ios::out);
	fin.open("test_1.csv", ios::in);
	if (!fout.is_open()){
		cout << "fout open fail!" << endl;
		return 0;
	}
	if (!fin.is_open()){
		cout << "fin open fail!" << endl;
		return 0;
	}
	string temp;
	getline(fin, temp);						//����

	unsigned int no, len, packet_seq, packet_ack, packet_len;
	double time;
	string src_ip, dst_ip, protocol, info, equal;
	while (fin >> no >> time >> src_ip >> dst_ip >> protocol >> len){
		//getline(fin, info);
		if (src_ip == myip){				//TCP Segment����������
			while (fin >> temp){
				if (temp == Syn){			//��ACK
					getline(fin, info);
					break;
				}
				if (temp == Seq){			//����Seq
					fin >> equal >> packet_seq;
				}
				else if (temp == Ack){		//����Ack
					fin >> equal >> packet_ack;
				}
				else if (temp == Len){		//����Len�����治ȥҪ�ٶ�
					fin >> equal >> packet_len;
					getline(fin, info);
					break;
				}
			}
			if (temp == Len){

			}
		}
		else if (dst_ip == myip){			//ACK���Է�����
			while (fin >> temp){
				if (temp == Syn){			//��ACK
					getline(fin, info);
					break;
				}
				if (temp == Seq){			//����Seq
					fin >> equal >> packet_seq;
				}
				else if (temp == Ack){		//����Ack�����治ȥҪ�ٶ�
					fin >> equal >> packet_ack;
					getline(fin, info);
					break;
				}
			}
			if (temp == Len){

			}
		}
	}
	return 0;
}