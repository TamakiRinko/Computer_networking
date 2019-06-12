#include<iostream>
#include<fstream>
#include<string>
using namespace std;

//string myip = "172.27.133.233";			//����IP��ַ
//string myip = "172.27.136.12";				//���̵�
string myip = "172.27.150.210";
//string myip = "172.27.131.155";				//���
string Seq = "Seq";
string Ack = "Ack";
string Len = "Len";
string Syn = "[SYN]";
string Syn_Ack = "[SYN";
string Dup_or_OutofOrder = "[TCP";
string Protocol = "TCP";

int current_seq = 0;
int current_len = 0;
int current_ack = 0;
int current_windowsize = 0;

int main(){
	ifstream fin;
	ofstream fout;
	//fout.open("result.csv", ios::out);
	//fout.open("resultlong.csv", ios::out);
	//fout.open("resultlong2.csv", ios::out);
	//fout.open("result1.csv", ios::out);
	fout.open("resultshort.csv", ios::out);



	//fin.open("test_1.csv", ios::in);
	//fin.open("last_1.csv", ios::in);
	//fin.open("last_2.csv", ios::in);
	//fin.open("upload_file_short.csv", ios::in); 
	//fin.open("long.csv", ios::in);
	//fin.open("long2.csv", ios::in);
	//fin.open("1txt.csv", ios::in);
	fin.open("short.csv", ios::in);
	if (!fout.is_open()){
		cout << "fout open fail!" << endl;
		return 0;
	}
	if (!fin.is_open()){
		cout << "fin open fail!" << endl;
		return 0;
	}
	string temp;
	string temp2;
	getline(fin, temp2);					//���У�������

	int no, len, packet_seq = 0, packet_ack = 0, packet_len = 0;
	double time;
	string src_ip, dst_ip, protocol, info, equal;
	while (fin >> no >> time >> src_ip >> dst_ip >> protocol >> len){
		if (protocol != Protocol){			//����TCP���ģ��Թ�
			getline(fin, info);
			continue;
		}
		//cout << time << "  ";
		//cout << src_ip << endl;
		//getline(fin, info);
		if (src_ip == myip){				//TCP Segment����������
			while (fin >> temp){
				if (temp == Syn || temp == Dup_or_OutofOrder || temp == Syn_Ack){			//����������
					getline(fin, info);
					break;
				}
				if (temp == Seq){			//����Seq
					fin >> equal >> packet_seq;
				}
				else if (temp == Len){		//����Len�����治ȥҪ�ٶ�
					fin >> equal >> packet_len;
					getline(fin, info);
					break;
				}
			}
			if (temp == Len){
				current_len = packet_len;
				current_seq = packet_seq;
				current_windowsize = current_len + current_seq - current_ack;
				fout << time << "," << current_windowsize << "," << packet_seq << "," << packet_len << "," << packet_ack << "\n";
			}
		}
		else if (dst_ip == myip){			//ACK���Է�����
			while (fin >> temp){
				if (temp == Syn || temp == Dup_or_OutofOrder || temp == Syn_Ack){			//����������
					getline(fin, info);
					break;
				}
				else if (temp == Ack){		//����Ack�����治ȥҪ�ٶ�
					fin >> equal >> packet_ack;
					getline(fin, info);
					break;
				}
			}
			if (temp == Ack){
				current_ack = packet_ack;
				current_windowsize = current_len + current_seq - current_ack;
				fout << time << "," << current_windowsize << "," << packet_seq << "," << packet_len << "," << packet_ack << "\n";
			}
		}
	}
	fin.close();
	fout.close();
	return 0;
}