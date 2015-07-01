/**
 * @file secure_buffer.hxx
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief C++ self-zeroizing buffer.
 */
#ifndef __DECAF_SECURE_BUFFER_HXX__
#define __DECAF_SECURE_BUFFER_HXX__ 1

#include <string>
#include <sys/types.h>

/** @cond internal */
#if __cplusplus >= 201103L
#define NOEXCEPT noexcept
#define DELETE = delete
#else
#define NOEXCEPT throw()
#define DELETE
#endif
/** @endcond */

namespace decaf {

/**@cond internal*/
/** Forward-declare sponge RNG object */
class Buffer;
class TmpBuffer;
class SecureBuffer;
/**@endcond*/
    
/** @brief An exception for when crypto (ie point decode) has failed. */
class CryptoException : public std::exception {
public:
    /** @return "CryptoException" */
    virtual const char * what() const NOEXCEPT { return "CryptoException"; }
};

/** @brief An exception for when crypto (ie point decode) has failed. */
class LengthException : public std::exception {
public:
    /** @return "CryptoException" */
    virtual const char * what() const NOEXCEPT { return "LengthException"; }
};

/** @brief Passed to constructors to avoid (conservative) initialization */
struct NOINIT {};

/** @brief Prototype of a random number generator.
 * FUTURE: Are the noexcept methods really noexcept?  What about self-reseeding RNGs?
 */
class Rng {
protected:
    /** Empty initializer */
    Rng() {}
    
    /** Not copyable */
    Rng(const Rng &) DELETE;
    
    /** Not copyable */
    Rng &operator=(const Rng &) DELETE;
    
public:
    /** @brief Read into a Buffer */
    virtual inline void read(Buffer &buffer) NOEXCEPT = 0;
    
    /** @brief Read into a value-passed (eg temporary) TmpBuffer. */
    inline void read(TmpBuffer buffer) NOEXCEPT;

    /** @brief Read into a SecureBuffer. */
    inline SecureBuffer read(size_t length) throw(std::bad_alloc);
};

/**
 * Securely zeorize contents of memory.
 */
static inline void really_bzero(void *data, size_t size) { decaf_bzero(data,size); }

/** A reference to a block of data, which (when accessed through this base class) is const. */
class Block {
protected:
    unsigned char *data_;
    size_t size_;

public:
    /** Empty init */
    inline Block() NOEXCEPT : data_(NULL), size_(0) {}
    
    /** Init from C string */
    inline Block(const char *data) NOEXCEPT : data_((unsigned char *)data), size_(strlen(data)) {}

    /** Unowned init */
    inline Block(const unsigned char *data, size_t size) NOEXCEPT : data_((unsigned char *)data), size_(size) {}
    
    /** Block from std::string */
    inline Block(const std::string &s) : data_(
    #if __cplusplus >= 201103L
        ((unsigned char *)&(s)[0])
    #else
        ((unsigned char *)(s.data()))
    #endif
    ), size_(s.size()) {}

    /** Get const data */
    inline const unsigned char *data() const NOEXCEPT { return data_; }

    /** Get the size */
    inline size_t size() const NOEXCEPT { return size_; }

    /** Autocast to const unsigned char * */
    inline operator const unsigned char*() const NOEXCEPT { return data_; }

    /** Convert to C++ string */
    inline std::string get_string() const {
        return std::string((const char *)data_,size_);
    }

    /** Slice the buffer*/
    inline Block slice(size_t off, size_t length) const throw(LengthException) {
        if (off > size() || length > size() - off)
            throw LengthException();
        return Block(data()+off, length);
    }
    
    /** @cond internal */
    inline decaf_bool_t operator>=(const Block &b) const NOEXCEPT DELETE;
    inline decaf_bool_t operator<=(const Block &b) const NOEXCEPT DELETE;
    inline decaf_bool_t operator> (const Block &b) const NOEXCEPT DELETE;
    inline decaf_bool_t operator< (const Block &b) const NOEXCEPT DELETE;
    /** @endcond */
    
    /* Content-wise comparison; constant-time if they are the same length. */ 
    inline decaf_bool_t operator!=(const Block &b) const NOEXCEPT {
        if (b.size() != size()) return true;
        return ~decaf_memeq(b,*this,size());
    }
    
    /* Content-wise comparison; constant-time if they are the same length. */ 
    inline decaf_bool_t operator==(const Block &b) const NOEXCEPT {
        return ~(*this == b);
    }

    /** Virtual destructor for SecureBlock. TODO: probably means vtable?  Make bool? */
    inline virtual ~Block() {};
};

/** A reference to a writable block of data */
class Buffer : public Block {
public:
    /** Null init */
    inline Buffer() NOEXCEPT : Block() {}

    /** Unowned init */
    inline Buffer(unsigned char *data, size_t size) NOEXCEPT : Block(data,size) {}

    /** Get unconst data */
    inline unsigned char *data() NOEXCEPT { return data_; }

    /** Get const data */
    inline const unsigned char *data() const NOEXCEPT { return data_; }

    /** Autocast to const unsigned char * */
    inline operator const unsigned char*() const NOEXCEPT { return data_; }

    /** Autocast to unsigned char */
    inline operator unsigned char*() NOEXCEPT { return data_; }

    /** Slice the buffer*/
    inline TmpBuffer slice(size_t off, size_t length) throw(LengthException);
    
    /** Securely set the buffer to 0. */
    inline void zeorize() NOEXCEPT { really_bzero(data(),size()); }
};

/** A temporary reference to a writeable buffer, for converting C to C++. */
class TmpBuffer : public Buffer {
public:
    /** Unowned init */
    inline TmpBuffer(unsigned char *data, size_t size) NOEXCEPT : Buffer(data,size) {}
};

/** A fixed-size stack-allocated buffer (for NOEXCEPT semantics) */
template<size_t Size> class StackBuffer : public Buffer {
private:
    uint8_t storage[Size];
public:
    /** New buffer initialized to zero. */
    inline StackBuffer() NOEXCEPT : Buffer(storage, Size) { memset(storage,0,Size); }

    /** New uninitialized buffer. */
    inline StackBuffer(const NOINIT &) NOEXCEPT : Buffer(storage, Size) { }
    
    /** New random buffer */
    inline StackBuffer(Rng &r) NOEXCEPT  : Buffer(storage, Size) { r.read(*this); }
    
    /** Destroy the buffer */
    ~StackBuffer() NOEXCEPT { zeorize(); }
};

/** @cond internal */
inline void Rng::read(TmpBuffer buffer) NOEXCEPT { read((Buffer &)buffer); }
/** @endcond */

/** A self-erasing block of data */
class SecureBuffer : public Buffer {
public:
    /** Null secure block */
    inline SecureBuffer() NOEXCEPT : Buffer() {}

    /** Construct empty from size */
    inline SecureBuffer(size_t size) {
        data_ = new unsigned char[size_ = size];
        memset(data_,0,size);
    }

    /** Construct from data */
    inline SecureBuffer(const unsigned char *data, size_t size) {
        data_ = new unsigned char[size_ = size];
        memcpy(data_, data, size);
    }
    
    /** Construct from random */
    inline SecureBuffer(Rng &r, size_t size) NOEXCEPT {
        data_ = new unsigned char[size_ = size];
        r.read(*this);
    }

    /** Copy constructor */
    inline SecureBuffer(const Block &copy) : Buffer() { *this = copy; }

    /** Copy-assign constructor */
    inline SecureBuffer& operator=(const Block &copy) throw(std::bad_alloc) {
        if (&copy == this) return *this;
        clear();
        data_ = new unsigned char[size_ = copy.size()];
        memcpy(data_,copy.data(),size_);
        return *this;
    }

    /** Copy-assign constructor */
    inline SecureBuffer& operator=(const SecureBuffer &copy) throw(std::bad_alloc) {
        if (&copy == this) return *this;
        clear();
        data_ = new unsigned char[size_ = copy.size()];
        memcpy(data_,copy.data(),size_);
        return *this;
    }

    /** Destructor zeorizes data */
    ~SecureBuffer() NOEXCEPT { clear(); }

    /** Clear data */
    inline void clear() NOEXCEPT {
        if (data_ == NULL) return;
        zeorize();
        delete[] data_;
        data_ = NULL;
        size_ = 0;
    }

#if __cplusplus >= 201103L
    /** Move constructor */
    inline SecureBuffer(SecureBuffer &&move) { *this = move; }

    /** Move non-constructor */
    inline SecureBuffer(Block &&move) { *this = (Block &)move; }

    /** Move-assign constructor. TODO: check that this actually gets used.*/ 
    inline SecureBuffer& operator=(SecureBuffer &&move) {
        clear();
        data_ = move.data_; move.data_ = NULL;
        size_ = move.size_; move.size_ = 0;
        return *this;
    }

    /** C++11-only explicit cast */
    inline explicit operator std::string() const { return get_string(); }
#endif
};

/** @cond internal */
TmpBuffer Buffer::slice(size_t off, size_t length) throw(LengthException) {
    if (off > size() || length > size() - off) throw LengthException();
    return TmpBuffer(data()+off, length);
}

inline SecureBuffer Rng::read(size_t length) throw(std::bad_alloc) {
    SecureBuffer out(length); read(out); return out;
}
/** @endcond */

} /* namespace decaf */


#undef NOEXCEPT
#undef DELETE

#endif /* __DECAF_SECURE_BUFFER_HXX__ */
