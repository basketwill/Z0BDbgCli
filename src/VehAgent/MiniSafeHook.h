#ifndef _CMiniSafeHook_H
#define _CMiniSafeHook_H
#pragma warning(disable:4995)
#include <windows.h>
namespace MiniSdk
{
	class CMiniSafeHook
	{
	public:
		CMiniSafeHook();
		~CMiniSafeHook();

		static BOOL Init();
		static void UnInit();


	private:

		static BOOL m_Init;

	public:
		static BOOL MH_Hook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal);
		static BOOL MH_UnHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal);
		static BOOL MH_MakeDynamicHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal);

		static BOOL MH_Hook_Api_Name(
			char* pApiName,
			char* pModuleName,
			LPVOID pDetour, LPVOID *ppOriginal
		);

		static BOOL MH_UnHook_Api_Name(
			char* pApiName,
			char* pModuleName
		);

		static BOOL MH_MakeStrategy(
			LPVOID* OnPreFilter,
			LPVOID* OnPostFilter,
			LPVOID* OnRealCall,
			char* ApiName,
			char* ModuleName,
			USHORT FlagsType,
			USHORT FilterNums,
			USHORT FilterMethod);

		static BOOL MH_EnableStrategy();
	};
};
#endif