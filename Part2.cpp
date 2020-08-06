#include <big.h>
#include <ecn.h>
#include <miracl.h>
#include <mirdef.h>
#include <iostream>
#include <fstream>

Miracl precision(20, MAXBASE);
using namespace std;

void test1() {
	ifstream curve_init("/home/weilu/miracl/secp256.ecs");
	int bits;
	Big a, b, p, q, x, y;
	ECn G, W;
	miracl *mip = &precision;
	mip->IOBASE = 10;
	curve_init >> bits;
	mip->IOBASE = 16;
	curve_init >> p >> a >> b >> q >> x >> y;
	mip->IOBASE = 10;
	//初始化椭圆曲线
	ecurve(a, b, p, MR_PROJECTIVE);
	G.set(x, y);
	W = G;
	cout << G << endl;
	W -= G;
	cout << W << endl;
}

void test2() {
	ifstream curve_init("/home/weilu/miracl/secp256.ecs");
	int bits;
	Big a, b, p, q, x, y;
	ECn G, W;
	miracl *mip = &precision;
	mip->IOBASE = 10;
	curve_init >> bits;
	mip->IOBASE = 16;
	curve_init >> p >> a >> b >> q >> x >> y;
	mip->IOBASE = 10;
	//初始化椭圆曲线
	ecurve(a, b, p, MR_PROJECTIVE);
	//初始化生成元
	G.set(x, y);
	W = G;
	//点加操作
	W += G;
	cout << "G+G=" << W << endl;
	W = G;
	//点乘操作
	W *= 3;
	cout << "3*G=" << W << endl;
}

void test3() {
	ifstream curve_init("/home/weilu/miracl/secp256.ecs");
	int bits;
	Big a, b, p, q, x, y;
	ECn G, PK_a,PK_b,K_a,K_b;
	Big sk_a,sk_b;
	miracl *mip = &precision;
	mip->IOBASE = 10;
	curve_init >> bits;
	mip->IOBASE = 16;
	curve_init >> p >> a >> b >> q >> x >> y;
	mip->IOBASE = 10;
	//初始化椭圆曲线
	ecurve(a, b, p, MR_PROJECTIVE);
	//初始化生成元
	G.set(x, y);
	//Alice,Bob分别生成公私钥
	sk_a = rand(q);
	sk_b = rand(q);
	PK_a = G;
	PK_a *= sk_a;
	PK_b = G;
	PK_b *= sk_b;
	//密钥协商
	K_a = PK_a;
	K_b = PK_b;
	//Alice计算方法
	K_b *= sk_a;
	//Bob计算方法
	K_a *= sk_b;
	cout << (K_a==K_b?"Successful key agreement process":"unsuccessful key agreement process") <<endl;
}

int main() {
	test3();
}
