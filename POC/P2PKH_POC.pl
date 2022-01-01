use Bitcoin::Crypto::Base58 qw(encode_base58 encode_base58check decode_base58);
use Bitcoin::Crypto qw(btc_pub btc_prv); 
use Digest::SHA qw(sha256_hex sha256);
use Crypt::RIPEMD160;
 
my $prv_key  = shift;

my $bytestr = decode_base58($prv_key);

print("PRV_KEY (base58):       ".$prv_key."\n");
print("PRV_KEY (hex)   :       ");
my $prv_hex=unpack "H*", $bytestr;
print($prv_hex."\n");

my $key4sha = substr($bytestr,0,length($bytestr)-4);

my $sha256_1hash = sha256($key4sha);
my $sha256_1hashh = sha256_hex($key4sha);
print("1st SHA256 (hex):       ".$sha256_1hashh."\n");
my $sha256_2hash = sha256($sha256_1hash);
my $sha256_2hashh = sha256_hex($sha256_1hash);
print("2st SHA256 (hex):       ".$sha256_2hashh."\n");

# Compare first 4 bytes of 2nd SHA256 with last 4 of PRV_KEY

if (substr($bytestr,length($bytestr)-4,4) eq substr($sha256_2hash,0,4)){
        print("\n# Hashed correctly - correct WIF private key given \n");
}else{
        print("\n# Hashed not correctly - private key given is not a real WIF format\n# Exiting...\n");
        exit();
}
 
$ripemd_context = Crypt::RIPEMD160->new;
print("\n# Compressed Key first\n");
my $prv = btc_prv->from_wif($prv_key);
$prv->set_compressed(1);
my $pub = $prv->get_public_key();
print "PUB_KEY compr(hex):     ".$pub->to_hex()."\n";
my $pub_sha256 = sha256($pub->to_bytes);
my $pub_sha256_hex = sha256_hex($pub->to_bytes);
print "SHA256 (hex):           ".$pub_sha256_hex."\n";
$ripemd_context->reset();
$ripemd_context->add($pub_sha256);
my $pub_ripemd160=$ripemd_context->digest();
print "RIPEMD160(SHA256)(hex): ".$ripemd_context->hexdigest()."\n";
my $pub_base58 = encode_base58check(chr(0).$pub_ripemd160);
print "PUB_KEY compr(P2PKH):   ".$pub_base58."\n";
print("\n# UnCompressed Key now\n");
$prv->set_compressed(0);
my $pub = $prv->get_public_key();
print "PRV_KEY uncompr(hex):   ".$pub->to_hex()."\n";
print "PUB_KEY compr(hex):     ".$pub->to_hex()."\n";
my $pub_sha256 = sha256($pub->to_bytes);
my $pub_sha256_hex = sha256_hex($pub->to_bytes);
print "SHA256 (hex):           ".$pub_sha256_hex."\n";
$ripemd_context->reset();
$ripemd_context->add($pub_sha256);
my $pub_ripemd160=$ripemd_context->digest();
print "RIPEMD160(SHA256)(hex): ".$ripemd_context->hexdigest()."\n";
my $pub_base58 = encode_base58check(chr(0).$pub_ripemd160);
print "PUB_KEY compr(P2PKH):   ".$pub_base58."\n";

