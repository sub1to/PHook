#ifndef HOOK_H
#define HOOK_H

class IPHook
{
public:
	virtual			~IPHook()		{ };

	virtual void*	target()		{ return nullptr; };
	virtual void*	trampoline()	{ return nullptr; };
	virtual void*	hook()			{ return nullptr; };
	virtual size_t	size()			{ return 0; };

	virtual bool	enable()		{ return 0; };
	virtual bool	disable()		{ return 0; };
	virtual bool	enabled()		{ return 0; };
};

class CPHook : protected IPHook
{
public:
	CPHook();
	virtual ~CPHook();

	void*	target();
	void*	trampoline();
	void*	hook();
	size_t	size();

	bool	enable();
	bool	disable();
	bool	enabled();

protected:
	BYTE*	m_pTraBuf;
	void*	m_pTarget;
	void*	m_pHook;
	size_t	m_ullHkSize;
	BYTE*	m_pHkBuf;
	BYTE*	m_pLJBuf;
	BYTE*	m_pOrigBuf;
	bool	m_bEnabled;
};

class CPHookRelJmp : protected CPHook
{
public:
	CPHookRelJmp(void* pTarget, void* pHook, size_t size);
	virtual ~CPHookRelJmp();
};

class CPHookVTable : protected CPHook
{
public:
	CPHookVTable(void* pTarget, void* pHook);
	virtual ~CPHookVTable();

	void*	trampoline();
};

class CPHookCall : protected CPHook
{
public:
	CPHookCall(void* pTarget, void* pHook, size_t size);
	virtual ~CPHookCall();
};

class CPHookPatch : protected CPHook
{
public:
	CPHookPatch(void* pTarget, void* pHook, size_t size);
	virtual ~CPHookPatch();
};


#endif //HOOK_H

