#include <big.h>
#include <flash.h>
#include <miracl.h>
#include <iostream>
#include <zzn.h>
Miracl precision(3072,2);

void test1() {
	// 150-bit 2进制随机数
	Big a=rand(150,2);
	cout << a <<endl;
	cout << bits(a) << endl;
}

void test2() {
	Flash frac(1,3);
	cout << "precision:200"<<endl;
	cout << "1/3:"<<frac<<endl;
}

void test3() {
	//第一种方法
	Big rand1=rand(256,2);
	cout << "rand number:" << rand1 << endl;
	cout << "size:" <<bits(rand1)<<endl;
	//第二种方法
	Big rand2=rand(rand1);
	cout << "rand number:" << rand2 << endl;
	cout << "size:" <<bits(rand2)<<endl;
	cout << "rand1>rand2?\t" << (rand1>rand2?"yes":"no") << endl;
}

void test4() {
	Big test_rand=rand(256,2);
	miracl *mip=&precision;
	//默认进制为10进制
	cout << "Base-10 output:"<< test_rand << endl;
	//修改进制为2进制
	mip->IOBASE=2;
	cout << "Base-2 output:"<< test_rand << endl;
	//修改进制为16进制
	mip->IOBASE=16;
	cout << "Base-16 output:"<< test_rand << endl;
	//修改进制为64进制(Base64编码)
	mip->IOBASE=64;
	cout << "Base-64 output:"<< test_rand << endl;
}

void test5() {
	//设置seed，每次运行都会生成相同的结果
	irand(123456);
	Big rand_base=rand(256,2);
	Big rand_num;
	for(int i=0;i<5;i++) {
		rand_num=rand(rand_base);
		cout << rand_num <<endl;
	}
}

void test6() {
	const static int big_rand_bitlen=256;
	Big rand_num=rand(big_rand_bitlen,2);
	char *array=new char[big_rand_bitlen/8];
	// Big变量转换成char *数组
	to_binary(rand_num,big_rand_bitlen/8,array);
	cout << array <<endl;
	// char*数组转换成Big变量
	Big recover=from_binary(big_rand_bitlen/8,array);
	cout << recover <<endl;
	cout << (recover==rand_num?"recover successfully":"recover unsuccessfully")<<endl;
}

void test7() {
	const char *ID="Anhui University";
	char output[20];
	sha sh;
	shs_init(&sh);
	while (*ID!=0) shs_process(&sh,*ID++);
	shs_hash(&sh,output);
	Big h=from_binary(20,output);
	cout << h << endl;
}

void test8() {
	aes a;
	// 初始向量
	char iv[16]={0,0,0,0,
	0,0,0,0,
	0,0,0,0,
	0,0,0,0};
	// 随机128位密钥，并存至char *数组
	Big key_big=rand(16*8,2);
	char key[16];
	to_binary(key_big,16,key);
	//AES128-CBC模式加密
	aes_init(&a,MR_CBC,16,key,iv);
	char text[32]="今天天气很好";
	cout << "plaintext:"<<text<<endl;
	aes_encrypt(&a,text);
	aes_end(&a);
	cout << "ciphertext:"<<text<<endl;
}

void test9() {
	miracl *mip=&precision;
	mip->IOBASE=16;
	Big x1=0xFFFFFFFF;
	mip->IOBASE=10;
	cout << x1 <<endl;
}

void test10() {
	// generator:1024-bit, exponent:160-bit
	Big mod;
	// find a prime modulo
	while(true) {
		Big temp=rand(1024,2);
		if(prime(temp)) {
			mod=temp;
			break;
		}
	}
	modulo(mod);
	// find a generator
	Big g;
	g=rand(mod);
	Big a=rand(160,2),b=rand(160,2);
	ZZn A,B,Ab,Ba;
	A=pow((ZZn)g,a);
	B=pow((ZZn)g,b);
	Ab=pow(A,b);
	Ba=pow(B,a);
	cout << "A:"<< A<< endl;cout << "B:"<< B <<endl;
	cout<< "a:" << a <<endl;cout<< "b:" << b <<endl;
	cout<< "Ab:" << Ab <<endl;cout<< "Ba:" << Ba <<endl;
	cout << (Ab==Ba?"A^b=B^a":"A^b!=B^a") <<endl;
}

void test11() {
	Big tmp1,tmp2,p,q,n,phi_n,d,e,m,c,_m;
	tmp1=rand(512,2);tmp2=rand(512,2);
	//Step1:任意选取两个不同的大素数p和q计算乘积n=pq
	p=nextprime(tmp1);q=nextprime(tmp2);
	n=p*q;
	phi_n=(p-1)*(q-1);
	//Step2:任意选取一个大整数e，满足gcd(e,phi(n))
	while(true) {
		e=rand(n);
		if((e!=1)& (gcd(e,phi_n)==1)) break;
	}
	//step3:确定的解密钥d，满足de mod phi_n =1
	d=inverse(e,phi_n);
	//step4:确定明文，映射到一个数
	m=rand(1000,2);
	// 加密m生成c,c=m^e mod n
	c=pow(m,e,n);
	//解密c生成m,m=c^d mod n
	_m=pow(c,d,n);
	cout << (_m==m?"Decrypt successfully":"Decrypt unsuccessfully") << endl;
}

void test12() {
	// generator:1024-bit, exponent:160-bit
	Big mod;
	// find a prime modulo
	while(true) {
		Big temp=rand(1024,2);
		if(prime(temp)) {
			mod=temp;
			break;
		}
	}
	modulo(mod);
	// find a generator
	Big g;
	g=rand(mod);
	Big a=rand(160,2),b=rand(160,2);
	ZZn A,B,Ab,Ba;
	A=pow((ZZn)g,a);B=pow((ZZn)g,b);
	ZZn m,c;
	// Alice加密m给Bob
	ZZn PK=pow(B,a);
	// 将m映射成数
	m=rand(1000,2);
	c=m*PK;
	// Bob解密Alice发送的c
	ZZn _PK=pow(A,b);
	ZZn _m=c/_PK;
	cout << (_m==m?"Decrypt successfully":"Decrypt unsuccessfully") <<endl;
}
int main() {
	test12();
}
