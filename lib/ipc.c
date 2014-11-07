// User-level IPC library routines

#include <inc/lib.h>

// Receive a value via IPC and return it.
// If 'pg' is nonnull, then any page sent by the sender will be mapped at
//	that address.
// If 'from_env_store' is nonnull, then store the IPC sender's envid in
//	*from_env_store.
// If 'perm_store' is nonnull, then store the IPC sender's page permission
//	in *perm_store (this is nonzero iff a page was successfully
//	transferred to 'pg').
// If the system call fails, then store 0 in *fromenv and *perm (if
//	they're nonnull) and return the error.
// Otherwise, return the value sent by the sender
//
// Hint:
//   Use 'thisenv' to discover the value and who sent it.
//   If 'pg' is null, pass sys_ipc_recv a value that it will understand
//   as meaning "no page".  (Zero is not the right value, since that's
//   a perfectly valid place to map a page.)
int32_t
ipc_recv(envid_t *from_env_store, void *pg, int *perm_store)
{
	int r;
//	cprintf("entering ipc recv\n");
        if (pg ==NULL)
        {
//		cprintf("pg=NULL\n");
	        pg = (void *) UTOP;
	}
        r = sys_ipc_recv((void *)pg);
        if (r<0)
        {
                if (from_env_store!=NULL)
		*from_env_store = 0;
		if (perm_store!= NULL)
                *perm_store = 0;
//		cprintf("entering 2 ipc recv\n");

                return r;
        }
        if (from_env_store!=NULL)
                *from_env_store = thisenv->env_ipc_from;
        if (perm_store!= NULL)
                *perm_store = thisenv->env_ipc_perm;
//	        cprintf("entering 3 ipc recv value=%08x\n",thisenv->env_ipc_value);
        return thisenv->env_ipc_value;

        //panic("ipc_recv not implemented");
        return 0;
	// LAB 4: Your code here.
	panic("ipc_recv not implemented");
	return 0;
}

// Send 'val' (and 'pg' with 'perm', if 'pg' is nonnull) to 'toenv'.
// This function keeps trying until it succeeds.
// It should panic() on any error other than -E_IPC_NOT_RECV.
//
// Hint:
//   Use sys_yield() to be CPU-friendly.
//   If 'pg' is null, pass sys_ipc_recv a value that it will understand
//   as meaning "no page".  (Zero is not the right value.)
void
ipc_send(envid_t to_env, uint32_t val, void *pg, int perm)
{
	 int r;
        if(pg == NULL)
                pg = (void *)UTOP;
//	cprintf("entering ipc_send val=%08x\n",val);
        while(1){
                r = sys_ipc_try_send(to_env, val, pg, perm);
                if (r == 0)
                        return;
                 else if (r != -E_IPC_NOT_RECV)
                  {      panic("panic in ipc_send");
			break;
			}
                sys_yield();
        }
//	cprintf("entering 2 ipc_send\n");
//	panic("ipc_send not implemented");
}

// Find the first environment of the given type.  We'll use this to
// find special environments.
// Returns 0 if no such environment exists.
envid_t
ipc_find_env(enum EnvType type)
{
	int i;
	for (i = 0; i < NENV; i++)
		if (envs[i].env_type == type)
			return envs[i].env_id;
	return 0;
}
