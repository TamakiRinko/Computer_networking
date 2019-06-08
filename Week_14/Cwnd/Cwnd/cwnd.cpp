#include<iostream>
#include<fstream>
#include<string>
using namespace std;

int main(){
	//FILE* fp;
	//fp = fopen("liquanlong3.xlsx", "r");
	string myip = "172.27.129.248";			//±¾»úIPµØÖ·
	ifstream fin;
	ofstream fout;
	fout.open("result", ios::out);
	fin.open("liquanlong3.csv", ios::in);
	if (!fout.is_open()){
		cout << "fout open fail!" << endl;
		return 0;
	}
	if (!fin.is_open()){
		cout << "fin open fail!" << endl;
		return 0;
	}
	string temp;
	getline(fin, temp);
	cout << temp << endl;
	int no, packet_len, seq, ack;
	double time;
	string src_ip, dst_ip, protocol;
	fin >> no >> time >> src_ip >> dst_ip >> protocol >> packet_len;
	getline(fin, temp);
	cout << no << endl << time << endl << src_ip << endl << dst_ip << endl << protocol << endl << packet_len << endl << temp << endl;
	fin >> no >> time >> src_ip >> dst_ip >> protocol >> packet_len;
	getline(fin, temp);
	cout << no << endl << time << endl << src_ip << endl << dst_ip << endl << protocol << endl << packet_len << endl << temp << endl;
	return 0;
}