#include "MiniSafeHook.h"
#include "MinHook.h"


#ifdef WIN64
#pragma comment(lib,"minhook_2010.x64.lib")
#else

#pragma comment(lib,"minhook_2010.lib")
#endif

namespace MiniSdk
{
	BOOL CMiniSafeHook::m_Init = FALSE;
	CMiniSafeHook::CMiniSafeHook()
	{

	}


	CMiniSafeHook::~CMiniSafeHook()
	{
		if (InterlockedCompareExchange((long*)&m_Init, 1, 1))
		{
			MH_Uninitialize();
			InterlockedExchange((long*)&m_Init, 0);
		}
	}


	BOOL CMiniSafeHook::Init()
	{
		if (InterlockedCompareExchange((long*)&m_Init, 0, 0) == 0)
		{
			InterlockedExchange((long*)&m_Init, MH_Initialize() == MH_OK);
		}


		if (InterlockedCompareExchange((long*)&m_Init, 1, 1))
		{
			return TRUE;
		}

		return FALSE;
	}

	void CMiniSafeHook::UnInit()
	{
		if (InterlockedCompareExchange((long*)&m_Init, 1, 1))
		{
			InterlockedExchange((long*)&m_Init, MH_Uninitialize() == MH_OK);
		}

	}

	BOOL CMiniSafeHook::MH_Hook_Api_Name(
		char* pApiName,
		char* pModuleName,
		LPVOID pDetour, LPVOID *ppOriginal
	)
	{
		if (Init() == TRUE)
		{
			LPVOID* pTarget = NULL;

			do 
			{
				if (!pApiName || !pModuleName)
				{
					break;
				}

				pTarget = (LPVOID*)GetProcAddress(
								GetModuleHandleA(pModuleName),
								pApiName);

				if (pTarget)
				{
					return MH_Hook(pTarget, pDetour, ppOriginal);
				}

			} while (FALSE);
			
		}

		return FALSE;
	}

	BOOL CMiniSafeHook::MH_UnHook_Api_Name(
		char* pApiName,
		char* pModuleName
	)
	{
		LPVOID* pTarget = NULL;

		do
		{
			if (!pApiName || !pModuleName)
			{
				break;
			}
			pTarget = (LPVOID*)GetProcAddress(
				GetModuleHandleA(pModuleName),
				pApiName);

			if (pTarget)
			{
				return (MH_DisableHook(pTarget) == MH_OK);
			}

		} while (FALSE);

		return FALSE;
	}

	BOOL CMiniSafeHook::MH_Hook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal)
	{
		if (Init() == TRUE)
		{
			do
			{
				__try
				{
					MH_STATUS Status = MH_CreateHook(pTarget,
						pDetour,
						ppOriginal);
					if (Status != MH_OK)
					{
						break;
					}

					// Enable the hook for
					if (MH_EnableHook(pTarget) != MH_OK)
					{
						break;
					}

					return TRUE;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{

				}

			} while (FALSE);

		}
		
		return FALSE;
	}

	BOOL CMiniSafeHook::MH_UnHook(
		LPVOID pTarget,
		LPVOID pDetour,
		LPVOID *ppOriginal)
	{
		return (MH_DisableHook(pTarget) == MH_OK);
	}

};