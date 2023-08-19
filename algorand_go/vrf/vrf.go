package vrf


import (
	"crypto/rand"
	"golang.org/x/crypto/ed25519"
)

func NewKeyPair() (pk []byte, sk []byte) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader);
	if (err != nil) {
		return nil, nil
	}
	return pk, sk;
}

func Evaluate(m []byte, pk []byte, sk []byte) (hash []byte, proof []byte) {
	proof, _ = ECVRF_prove(pk, sk, m);
	hash = ECVRF_proof2hash(proof);
	return;
}

func Verify(pk []byte, proof []byte, m []byte) (status bool) {
	status, _ = ECVRF_verify(pk, proof, m);
	return;
}

/*
//export NewKeyPair
func NewKeyPair() (pk_void unsafe.Pointer, sk_void unsafe.Pointer) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader);
	if (err != nil) {
		return nil, nil
	}
	return C.CBytes(pk), C.CBytes(sk);
} 
*/


/*
//export Evaluate
func Evaluate(m *C.char, pk_void unsafe.Pointer, sk_void unsafe.Pointer) (hash_void unsafe.Pointer, proof_void unsafe.Pointer) {
	pk := C.GoBytes(pk_void, 32);
	sk := C.GoBytes(sk_void, 64);
	go_m := []byte(C.GoString(m));
	proof, _ := ECVRF_prove(pk, sk, go_m);
	hash := ECVRF_proof2hash(proof);
	
	return C.CBytes(hash), C.CBytes(proof);
}
*/


/*
//export Verify
func Verify(pk_void unsafe.Pointer, proof_void unsafe.Pointer, m *C.char) (status *C.char) {
	pk := C.GoBytes(pk_void, 32);
	proof := C.GoBytes(proof_void, 81);
	go_m := []byte(C.GoString(m));
	go_status, _ := ECVRF_verify(pk, proof, go_m);
	if (go_status == true) {
		return C.CString("Success");
	}
	return C.CString("Failed");
}
*/


/*
//export FreeUnsafePtr
func FreeUnsafePtr(ptr unsafe.Pointer) {
	C.free(ptr);
}


func main() {}
*/