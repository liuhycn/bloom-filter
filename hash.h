
class awareHash
{
private:
	u_int64 m;
	u_int64 hash_t;
	u_int64 scale_t;
	u_int64 hardener_t;
public:
	awareHash(){}
	awareHash(u_int64 hash, u_int64 scale, u_int64 hardener, u_int64 m)
	{
		this->hash_t = hash;
		this->scale_t = scale;
		this->hardener_t = hardener;
		this->m = m;
	}
	u_int64 hash(fiveTuple_t pktTuple);
};

uint64 awareHash::hash(fiveTuple_t pktTuple)
{
	u_char* data = pktTuple.str;
	uint64 n = 13;
	u_int64 hash = this->hash_t;
	u_int64 scale = this->scale_t;
	u_int64 hardener = this->hardener_t;

	while (n) 
	{
		hash *= scale;
		hash += *data++;
		n--;
	}
	return (hash ^ hardener) % this->m;
}
