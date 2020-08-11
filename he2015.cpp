/*
 * 此程序实现He2015TIFS论文
 * 安全强度为128-bit AES-security
 * 需要c++11,编译时加上-std=c++11
*/
#include <big.h>
#include <ecn.h>
#include <miracl.h>
#include <mirdef.h>
#include <iostream>
#include <fstream>
#include <time.h>
#include <chrono>
#include <utility>
#include <tuple>
//#include <math.h>
#include <vector>
#include <algorithm>


//Miracl precision(20, MAXBASE);
Miracl precision(1024,2);
const static int POINTXY_BYTESIZE=100;
//const static int SMALLVECTOR_BITSIZE=10;
static tuple<Big,ECn,ECn,Big> keys;
using namespace std;

//获取当前时间戳
Big getCurTimestamp() {
	chrono::time_point<chrono::system_clock, chrono::milliseconds> tp =
			chrono::time_point_cast<chrono::milliseconds>(
					chrono::system_clock::now()); //获取当前时间点
	time_t timestamp = tp.time_since_epoch().count(); //计算距离1970-1-1,00:00的时间长度
	return timestamp;
}


//初始化曲线
static void  init_curve(Big &q,ECn &G) {
	ifstream curve_init("/home/weilu/miracl/secp256.ecs");
	int bits;
	Big a, b, p, x, y;
	miracl *mip = &precision;
	mip->IOBASE = 10;
	curve_init >> bits;
	mip->IOBASE = 16;
	curve_init >> p >> a >> b >> q >> x >> y;
	mip->IOBASE = 10;
	//初始化椭圆曲线
	ecurve(a, b, p, MR_PROJECTIVE);
	G.set(x, y);
}

//生成系统公私钥匙
 const static void genKeys() {
	Big order;
	ECn generator;
	init_curve(order,generator);
//	cout <<generator<<endl;
	Big sk=rand(order);
	ECn PK=generator;
	PK*=sk;
	get<0>(keys)=sk;
	get<1>(keys)=PK;
	get<2>(keys)=generator;
	get<3>(keys)=order;
}

//获取生成元
const ECn getGenerator() {
	return get<2>(keys);
}

//获取群的阶
const Big getOrder() {
	return get<3>(keys);
}

//获取私钥
const Big getSystemPrivateKey() {
	return get<0>(keys);
}

//获取公钥
const ECn getSystemPublicKey() {
	return get<1>(keys);
}

Big h2(const char *input, Big order);
//h1:G->Z_q*
Big h1(const ECn *input, Big order) {
	Big x,y;
	input->get(x,y);
	char *ichar1=new char[POINTXY_BYTESIZE],*ichar2=new char[POINTXY_BYTESIZE];
	ichar1<<x;
	ichar2<<y;
	const string &istring=string(ichar1)+string(ichar2);
	const char *ichar=istring.c_str();
	return h2(ichar,order);
}

//h2:{0,1}*->Z_q* ps:作为基hash function
Big h2(const char *input, Big order) {
	char s[32];
	sha256 sh;
	shs256_init(&sh);
	while (*input!=0) shs256_process(&sh,*input++);
	shs256_hash(&sh,s);
	Big output=from_binary(32,s);
	return output % order;
}


//h3:{0,1}*\plus{0,1}*\plus G  \plus{0,1}*->Z_q*
Big h3(ECn pidi1, Big pidi2, Big ti, ECn Ri, const char * mi, Big q) {
	Big pidi1x,pidi1y,Rix,Riy;
	pidi1.getxy(pidi1x,pidi1y);
	Ri.getxy(Rix,Riy);
	char *pidi1x_char=new char[POINTXY_BYTESIZE],*pidi1y_char=new char[POINTXY_BYTESIZE],
			*pidi2_char=new char[POINTXY_BYTESIZE],*ti_char=new char[POINTXY_BYTESIZE],
			*Rix_char=new char[POINTXY_BYTESIZE],*Riy_char=new char[POINTXY_BYTESIZE];
	pidi1x_char<<pidi1x;
	pidi1y_char<<pidi1y;
	pidi2_char<<pidi2;
	ti_char<<ti;
	Rix_char<<Rix;
	Rix_char<<Riy;
	const string &istring=string(pidi1x_char)+string(pidi1y_char)+string(pidi2_char)+
			string(ti_char)+string(Rix_char)+string(Riy_char)+string(mi);
	const char *ichar=istring.c_str();
	return h2(ichar,q);
}

// 生成 alpha_i
Big genAlphai(ECn pidi1, Big pidi2, Big ti, Big q) {
	Big pidi1x,pidi1y;
	pidi1.getxy(pidi1x,pidi1y);
	char *pidi1x_char=new char[POINTXY_BYTESIZE],*pidi1y_char=new char[POINTXY_BYTESIZE],
			*pidi2_char=new char[POINTXY_BYTESIZE],*ti_char=new char[POINTXY_BYTESIZE];
	pidi1x_char<<pidi1x;
	pidi1y_char<<pidi1y;
	pidi2_char<<pidi2;
	ti_char<<ti;
	const string str=string(pidi1x_char)+string(pidi1y_char)+string(pidi2_char)+string(ti_char);
	const char *pidti_char=str.c_str();
	Big alphai=h2(pidti_char,q);
	return alphai;
}

// 生成 Beta_i
Big genBetai(ECn pidi1, Big pidi2, Big ti, ECn Ri, const char * mi, Big q) {
	return h3(pidi1, pidi2, ti, Ri, mi, q);
}

//车辆的TPD生成 PID_i,sk_i,T_i
//void TPDGen(tuple<pair<ECn, Big>,Big,Big> &input_tuple)
void TPDGen(ECn &out_pidi1, Big &out_pidi2,Big &out_ski, Big &out_ti) {
	Big ssk=getSystemPrivateKey();
	Big q=getOrder();
	ECn P=getGenerator();
	//step1:生成假名&RID
	Big ridi=rand(100,2);
	Big wi=rand(q);
	ECn pidi1=P;
	pidi1*=wi;
	ECn tmp=getSystemPublicKey();
	tmp*=wi;
	Big pidi2=h1(&tmp,q);
	pidi2=lxor(pidi2,ridi);
	pair<ECn,Big> pidi(pidi1,pidi2);
	//step2:生成ski
	//step 2.1:生成alpha_i
	Big ti=getCurTimestamp();
	cout <<"tpd-pidi1"<<pidi1<<endl;
	cout <<"tpd-pidi2"<<pidi2<<endl;
	cout <<"tpd-ti"<<ti<<endl;
	Big alphai=genAlphai(pidi1,pidi2,ti,q);
//	cout << "veh gen alpha:" <<alphai <<endl;
	//step 2.2:生成ski,Ri
	Big ski=(wi+alphai*ssk) % q;
	//test
	ECn left=P;
	left*=ski;
	ECn right;
	right=mul(1,pidi1,alphai,getSystemPublicKey());
	ECn test=P;
	test*=ssk;
/*	cout << "tpd-wiP"<<pidi1<<endl;
	cout << "tpd-Ppub"<<getSystemPublicKey()<<endl;
	cout << "tpd-alphai:"<<alphai<<endl;*/
	cout << "ski*P="<<left<<endl;
	cout << "wi*P+alphai*Ppub="<<right<<endl;
	//输出Pid_i,sk_i,T_i
	out_pidi1=pidi1;
	out_pidi2=pidi2;
	out_ski=ski;
	out_ti=ti;
}

// 车辆输出Mi,AIDi,Ti,Ri,sigmai
// 参数1：输入，参数2：输出
//void vehGen(tuple<pair<ECn, Big>,Big,Big> &input_tuple,tuple<const char *,pair<ECn, Big>,Big,ECn,Big> &output_tuple)
void vehGen(char *&out_mi, ECn &out_pidi1, Big &out_pidi2, Big &out_ti, ECn &out_Ri, Big &out_sigmai) {
	ECn in_pidi1;
	Big in_pidi2;
	Big in_ski;
	Big in_ti;
	TPDGen(in_pidi1, in_pidi2,in_ski, in_ti);
	Big ssk=getSystemPrivateKey();
	Big q=getOrder();
	ECn P=getGenerator();
	//step1:生成ri,Ri
	Big ri=rand(q);
	ECn Ri=P;
	Ri*=ri;
//	cout <<"Ri is:"<<Ri<<endl;
	//step2:生成msg，计算betai
//	out_mi="车辆们好！";
	cout <<"ver-pidi1"<<in_pidi1<<",pidi2:"<<in_pidi2<<",ti:"<<in_ti<<",Ri:"<<Ri<<",mi:"<<out_mi<<",q:"<<q<<endl;
	Big betai=genBetai(in_pidi1,in_pidi2,in_ti,Ri,out_mi,q);

	//step3:计算sigmai
	Big sigmai=(in_ski+betai*ri) % q;
	//test part:
	ECn leftP=P;leftP*=sigmai;
	ECn right1=P;right1*=in_ski;
	ECn right2=Ri;right2*=betai;
	ECn right=right1;right1+=right2;
	ECn _right;
	/*cout << "sigma*P="<<leftP << endl;
	cout << right << endl;*/
	_right=mul(in_ski,P,betai,Ri);
	/*cout << "tpd:betai*Ri="<<betai*Ri<<endl;
	cout << "tpd:betai="<<betai<<endl;
	cout << "ski*P+betai*Ri="<<_right << endl;*/
	//step4:output
	out_pidi1=in_pidi1;
	out_pidi2=in_pidi2;
	out_ti=in_ti;
	out_Ri=Ri;
	out_sigmai=sigmai;
}

// 消息接收车辆验证消息(单个认证)
/*bool vehSingleVerify(tuple<const char *,pair<ECn, Big>,Big,ECn,Big> &msg) {
	Big q=getOrder();
	ECn P=getGenerator();
	ECn Ppub=getSystemPublicKey();
	//提取具体内容
	const char *mi=get<0>(msg);
	pair<ECn,Big> pidi=get<1>(msg);
	Big ti=get<2>(msg);
	ECn Ri=get<3>(msg);
//	cout << "Ri is:"<<Ri<<endl;
	Big sigmai=get<4>(msg);
	//计算alphai
	ECn pidi1=pidi.first;
	Big pidi2=pidi.second;
	Big alphai=genAlphai(pidi1,pidi2,ti,q);
//	cout << "veh gen pidi2:"<<pidi2<<",ti:"<<ti<<",pidi1"<<pidi1<<endl;
	//计算betai
	Big betai=genBetai(pidi1,pidi2,ti,Ri,mi,q);
	//验证消息
	ECn left=P;
	left*=sigmai;
	ECn right;
	right=mul((Big)1,pidi.first,alphai,Ppub);
	right=mul((Big)1,right,betai,Ri);
	return (left==right);
}*/

//bool vehSingleVerify(tuple<const char *,pair<ECn, Big>,Big,ECn,Big> &msg)
bool vehSingleVerify(char *mi, ECn &pidi1, Big &pidi2, Big &ti, ECn &Ri, Big &sigmai){
	Big q=getOrder();
	ECn P=getGenerator();
	ECn Ppub=getSystemPublicKey();
	//提取具体内容
	/*cout <<"ver-pidi1"<<pidi1<<endl;
	cout <<"ver-pidi2"<<pidi2<<endl;
	cout <<"ver-ti"<<ti<<endl;*/
	Big alphai=genAlphai(pidi1,pidi2,ti,q);
//	cout << "veh gen pidi2:"<<pidi2<<",ti:"<<ti<<",pidi1"<<pidi1<<endl;
	//计算betai
	cout <<"ver-pidi1"<<pidi1<<",pidi2:"<<pidi2<<",ti:"<<ti<<",Ri:"<<Ri<<",mi:"<<mi<<",q:"<<q;
	Big betai=genBetai(pidi1,pidi2,ti,Ri,mi,q);
	//验证消息
	ECn left;
	left=sigmai*P;
	ECn right;
	right=mul(1,pidi1,alphai,Ppub);
	/*cout <<"ver-wiP:"<<pidi1<<endl;
	cout <<"ver-Ppub:"<<Ppub<<endl;
	cout <<"ver-alphai"<<alphai<<endl;*/
	cout << "right point:wiP+alphai*Ppub" <<right<<endl;
	cout << "tpd:betai="<<betai<<endl;
	cout << "ver:betai*Ri="<<betai*Ri<<endl;
	right=mul(1,right,betai,Ri);
	/*right+=(alphai*Ppub);
	right+=(betai*Ri);*/
	cout << "left point" <<left<<endl;
	cout << "right point" <<right<<endl;
	cout << "msg:"<<mi<<endl;
	cout << "ti:"<<ti<<endl;
	return (left==right);
}

// 消息接收车辆验证消息(批认证)
/*
bool vehBatchVerify(vector<tuple<const char *,pair<ECn, Big>,Big,ECn,Big>> &msgVector) {
	int size=msgVector.size();
	//加载系统参数
	Big q=getOrder();
	ECn P=getGenerator();
	ECn Ppub=getSystemPublicKey();
	//初始化变量
	Big sum_signature=0;
	ECn sum_pidi1=q*P;
	Big sum_alphai=0;
	ECn sum_betaRi=q*P;

	for (int i=0;i<size;i++) {
		//提取具体内容
		const char *mi=get<0>(msgVector[i]);
		pair<ECn,Big> pidi=get<1>(msgVector[i]);
		Big ti=get<2>(msgVector[i]);
		ECn Ri=get<3>(msgVector[i]);
		Big sigmai=get<4>(msgVector[i]);
		//计算alphai
		ECn pidi1=pidi.first;
		Big pidi2=pidi.second;
		Big alphai=genAlphai(pidi1,pidi2,ti,q);
		//计算betai
		Big betai=genBetai(pidi1,pidi2,ti,Ri,mi,q);
		//生成随机小变量
//		Big vi=rand(SMALLVECTOR_BITSIZE,2);
//		Big vi=2;
		//计算左式累加签名
		sum_signature+=(sigmai);
		//计算右式累加pidi1
//		sum_pidi1=mul(1,sum_pidi1,vi,pidi1);
		sum_pidi1+=pidi1;
		//计算右式累加alphai
		sum_alphai+=(alphai);
		//计算右式累加
//		sum_betaRi=mul(1,sum_betaRi,(vi*betai) ,Ri);
		ECn tmp=(betai)*Ri;
		sum_betaRi+=tmp;
	}
	//验证
	ECn left;
	cout << left<<endl;
//	left=mul(1,left,sum_signature,P);
	left=sum_signature*P;
	Big x;
	left.getx(x);
	cout << "left x:"<<x<<endl;
//	cout << (sum_signature>=q?"over":"not over") <<endl;
//	left*=(sum_signature % q);
	ECn right;
//	cout <<(sum_alphai>=q?"over":"not over")<<endl;
	right=mul(1,right,1,sum_pidi1);
	right=mul(1,right,sum_alphai,Ppub);
	right=mul(1,right,1,sum_betaRi);
	right=sum_pidi1;
	right+=(sum_alphai*Ppub);
	right+=sum_betaRi;
	Big x1;
	right.getx(x1);
	cout << "right x:"<<x1<<endl;
	return (left==right);
}
*/

bool vehBatchVerify(vector<tuple<const char *,pair<ECn, Big>,Big,ECn,Big>> &msgVector) {
	int size=msgVector.size();
	//加载系统参数
	Big q=getOrder();
	ECn P=getGenerator();
	ECn Ppub=getSystemPublicKey();
	//初始化变量
	ECn left,right;

	for (int i=0;i<size;i++) {
		//提取具体内容
		const char *mi=get<0>(msgVector[i]);
		pair<ECn,Big> pidi=get<1>(msgVector[i]);
		Big ti=get<2>(msgVector[i]);
		ECn Ri=get<3>(msgVector[i]);
		Big sigmai=get<4>(msgVector[i]);
		//计算alphai
		ECn pidi1=pidi.first;
		Big pidi2=pidi.second;
		Big alphai=genAlphai(pidi1,pidi2,ti,q);
		//计算betai
		Big betai=genBetai(pidi1,pidi2,ti,Ri,mi,q);

		left+=(sigmai*P);
		right+=pidi1;
		right+=(alphai*Ppub);
		right+=(betai*Ri);
		right-=(q*P);
	}
	//验证
	cout << "left x:"<<left<<endl;
	cout << "right:"<<right<<endl;
	return (left==right);
}

// 测试批认证
/*void testBatchVerification(const int maxTestNumber=9) {
	vector<tuple<const char *,pair<ECn, Big>,Big,ECn,Big>> msgVector;
	for (int i=0;i<maxTestNumber;i++) {
		tuple<pair<ECn, Big>,Big,Big> tu_in;
		TPDGen(tu_in);
		tuple<const char *,pair<ECn, Big>,Big,ECn,Big> tu_out;
		vehGen(tu_in,tu_out);
		cout <<"single verification:" <<vehSingleVerify(tu_out) <<endl;
		msgVector.push_back(tu_out);
	}
	tuple<const char *,pair<ECn, Big>,Big,ECn,Big> tu_out=msgVector;
	cout <<"single verification outside:" <<vehSingleVerify(tu_out) <<endl;
	cout << "special location: "<<vehSingleVerify(msgVector[5])<<endl;
	cout << maxTestNumber<<
			"辆车发送的消息"<<(vehBatchVerify(msgVector)==true?"通过":"未通过")<<"批认证!"<<endl;
}*/
int main() {
//	test3();
//	cout<<getCurTimestamp()<<endl;
//	cout<<getSystemPrivateKey()<<endl;
	genKeys();

	char *mi="test";
	ECn pidi1,Ri;
	Big pidi2,ti,sigmai;
	vehGen(mi, pidi1, pidi2, ti, Ri, sigmai);
	cout << "new single v test:"<<vehSingleVerify(mi, pidi1, pidi2, ti, Ri, sigmai)<<endl;

	/*tuple<pair<ECn, Big>,Big,Big> tu_in;
	TPDGen(tu_in);
	tuple<const char *,pair<ECn, Big>,Big,ECn,Big> tu_out;
	vehGen(tu_in,tu_out);
	cout << vehSingleVerify(tu_out) <<endl;*/

	cout <<"order size:"<<bits(getOrder())<<endl;
//	testBatchVerification(9);
}
