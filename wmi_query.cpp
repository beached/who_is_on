// The MIT License (MIT)
// 
// Copyright (c) 2016 Darrell Wright
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#define _WIN32_DCOM
#ifndef UNICODE
#define UNICODE
#endif
#include <atlsafe.h>
#include <exception>
#include <boost/program_options.hpp>
#include <iostream>
#include <sstream>
#include <comdef.h>
#include <Wbemidl.h>


#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")
#include <wincred.h>
#include <strsafe.h>
#include <atlbase.h>

#include "wmi_query.h"
#include "helpers.h"

namespace daw {
	namespace wmi {
		IWbemWrapper::IWbemWrapper( CComPtr<IWbemClassObject> obj ): m_obj( std::move( obj ) ) { }

		bool IWbemWrapper::operator( )( boost::wstring_ref property_name, std::wstring& out_value ) {
			return helpers::get_property( m_obj, property_name, out_value );
		}

		namespace impl {

			class COMConnection {
				COMConnection( ) {
					// Initialize COM
					auto hres = CoInitializeEx( nullptr, COINIT_MULTITHREADED );
					if( FAILED( hres ) ) {
						std::stringstream ss;
						ss << "Failed to initialize COM library. Error code = 0x" << std::hex << hres << ":" << _com_error( hres ).ErrorMessage( );
						throw std::runtime_error( ss.str( ) );
					}

					// Set general COM security levels
					if( FAILED( hres = CoInitializeSecurity( nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY, nullptr, EOAC_NONE, nullptr ) ) ) {
						std::stringstream ss;
						ss << "Failed to initialize security. Error code = 0x" << std::hex << hres << ":" << _com_error( hres ).ErrorMessage( );
						throw std::runtime_error( ss.str( ) );
					}

				}
			public:
				friend std::shared_ptr<COMConnection> create_com_connection( );

				~COMConnection( ) {
					CoUninitialize( );
				}
			};	// class COMConnection

			std::shared_ptr<COMConnection> create_com_connection( ) {
				static auto cc = std::shared_ptr<COMConnection>( []( ) {
					COMConnection * result = nullptr;
					try {
						result = new COMConnection( );
					} catch( ... ) {
						result = nullptr;
						throw;
					}
					return result;
				}() );
				return cc;
			}
			Authentication::Authentication( bool PromptCredentials, bool UseNtlm ): m_name { }, m_password { }, m_domain { }, m_user_name { }, m_authority { }, m_use_token( true ), m_use_ntlm( UseNtlm ), m_auth_ident( { } ), m_user_account( nullptr ) {
				if( PromptCredentials ) {
					CREDUI_INFO cui { };
					cui.cbSize = sizeof( CREDUI_INFO );
					cui.hwndParent = nullptr;
					// Ensure that MessageText and CaptionText identify
					// what credentials to use and which application requires them.
					cui.pszMessageText = TEXT( "Press cancel to use current user's token" );
					cui.pszCaptionText = TEXT( "Enter Account Information" );
					cui.hbmBanner = nullptr;
					BOOL f_save = FALSE;
					DWORD const credential_flags = CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_ALWAYS_SHOW_UI | CREDUI_FLAGS_DO_NOT_PERSIST;
					auto const dw_error = CredUIPromptForCredentials( &cui, TEXT( "" ), nullptr, 0, m_name.value, static_cast<ULONG>(m_name.size( )), m_password.value, static_cast<ULONG>(m_password.size( )), &f_save, credential_flags );
					if( ERROR_CANCELLED == dw_error ) {
						m_use_token = true;
					} else if( dw_error ) {
						std::stringstream ss;
						ss << "Did not get credentials " << dw_error;
						throw std::runtime_error( ss.str( ) );
					} else {
						m_use_token = false;
					}
				}
				// change the computerName strings below to the full computer name
				// of the remote computer
				if( !m_use_ntlm ) {
					StringCchPrintf( m_authority.value, m_authority.size( ), L"kERBEROS:%s", L"COMPUTERNAME" );
				}

				// Build ident
				if( !m_use_token ) {
					m_auth_ident.PasswordLength = static_cast<ULONG>(wcslen( m_password.value ));
					m_auth_ident.Password = reinterpret_cast<USHORT*>(m_password.value);

					auto slash = reinterpret_cast<LPWSTR>(wcschr( m_name.value, L'\\' ));
					if( nullptr == slash ) {
						throw std::runtime_error( "Could not create Auth identity. No domain specified" );
					}

					StringCchCopy( m_user_name.value, m_user_name.size( ), slash + 1 );
					m_auth_ident.User = reinterpret_cast<USHORT*>(m_user_name.value);
					m_auth_ident.UserLength = static_cast<ULONG>(wcslen( m_user_name.value ));

					StringCchCopyN( m_domain.value, m_domain.size( ), m_name.value, slash - m_name.value );
					m_auth_ident.Domain = reinterpret_cast<USHORT*>(m_domain.value);
					m_auth_ident.DomainLength = static_cast<ULONG>(slash - m_name.value);
					m_auth_ident.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

					m_user_account = &m_auth_ident;
				}

			}

			Authentication::sec_array &Authentication::name( ) {
				return m_name;
			}

			CComBSTR Authentication::name_bstr( ) const {
				if( m_use_token ) {
					return CComBSTR( nullptr );
				}
				return CComBSTR( m_name.value );
			}

			Authentication::sec_array & Authentication::password( ) {
				return m_password;
			}

			CComBSTR Authentication::password_bstr( ) const {
				if( m_use_token ) {
					return CComBSTR( nullptr );
				}
				return CComBSTR( m_password.value );
			}

			Authentication::sec_array & Authentication::domain( ) {
				return m_domain;
			}


			Authentication::sec_array & Authentication::authority( ) {
				return m_authority;
			}

			CComBSTR Authentication::authoriy_bstr( ) const {
				if( m_use_ntlm ) {
					return CComBSTR( nullptr );
				}
				return CComBSTR( m_authority.value );
			}

			bool & Authentication::use_token( ) {
				return m_use_token;
			}

			bool & Authentication::use_ntlm( ) {
				return m_use_ntlm;
			}

			COAUTHIDENTITY* Authentication::user_account( ) {
				return m_user_account;
			}

			CComPtr<IWbemLocator> obtain_wmi_locator( ) {
				// Obtain the initial locator to WMI 
				auto com_connection = create_com_connection( );

				CComPtr<IWbemLocator> locator;
				HRESULT hres;
				if( FAILED( hres = CoCreateInstance( CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<LPVOID *>(&locator) ) ) ) {
					std::stringstream ss;
					ss << "Failed to create IWbemLocator object. Err code = 0x" << std::hex << hres << ":" << _com_error( hres ).ErrorMessage( );
					throw std::runtime_error( ss.str( ) );
				}
				return locator;
			}

			CComPtr<IWbemServices> connect_to_server( boost::wstring_ref& host, CComPtr<IWbemLocator> pLoc, Authentication& auth ) {
				CComPtr<IWbemServices> pSvc;

				// Connect to the remote root\cimv2 namespace
				// and obtain pointer pSvc to make IWbemServices calls.
				//---------------------------------------------------------
				auto const wmi_str = L"\\\\" + host.to_string( ) + L"\\root\\cimv2";
				HRESULT hres;
				if( FAILED( hres = pLoc->ConnectServer( CComBSTR( wmi_str.c_str( ) ), auth.name_bstr( ), auth.password_bstr( ), nullptr, 0, auth.authoriy_bstr( ), nullptr, &pSvc ) ) ) {
					std::stringstream ss;
					ss << "Failed to create IWbemLocator object. Err code = 0x" << std::hex << hres << ":" << _com_error( hres ).ErrorMessage( );
					throw std::runtime_error( ss.str( ) );
				}
				return pSvc;
			}

			void set_wmi_security( CComPtr<IWbemServices> pSvc, Authentication &auth ) {
				HRESULT hres;
				if( FAILED( hres = CoSetProxyBlanket( pSvc, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, auth.user_account( ), EOAC_NONE ) ) ) {
					std::stringstream ss;
					ss << "Could not set proxy blanket. Error code = 0x" << std::hex << hres << ":" << _com_error( hres ).ErrorMessage( );
					throw std::runtime_error( ss.str( ) );
				}
			}

			void secure_wmi_enumerator( CComPtr<IEnumWbemClassObject> pEnumerator, Authentication &auth ) {
				HRESULT hres;
				if( FAILED( hres = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, auth.user_account( ), EOAC_NONE ) ) ) {
					std::stringstream ss;
					ss << "Could not set proxy blanket on enumerator. Error code = 0x" << std::hex << hres << ":" << _com_error( hres ).ErrorMessage( );
					throw std::runtime_error( ss.str( ) );
				}
			}

			CComPtr<IWbemClassObject> enumerator_next( CComPtr<IEnumWbemClassObject> query_enumerator ) {
				CComPtr<IWbemClassObject> value;

				ULONG value_type = 0;

				auto hres = query_enumerator->Next( WBEM_INFINITE, 1, &value, &value_type );
				if( FAILED( hres ) ) {
					std::stringstream ss;
					ss << "Error getting next object from query. Error code = 0x" << std::hex << hres << ":" << _com_error( hres ).ErrorMessage( );
					throw std::runtime_error( ss.str( ) );
				} else if( 0 == value_type ) {
					// TODO figure out better
					throw SkipRowException( );
				}
				return value;
			}

			CComPtr<IEnumWbemClassObject> execute_wmi_query( CComPtr<IWbemServices> pSvc, boost::string_ref &query ) {
				auto const wmi_query = CComBSTR( query.data( ) );
				auto const wql = CComBSTR( "WQL" );
				HRESULT hres;
				// Use the IWbemServices pointer to make WMI query
				CComPtr<IEnumWbemClassObject> pEnumerator = nullptr;
				if( FAILED( hres = pSvc->ExecQuery( wql, wmi_query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnumerator ) ) ) {
					std::stringstream ss;
					ss << "Query for Security Eventlog. Error code = 0x" << std::hex << hres << ":" << _com_error( hres ).ErrorMessage( );
					throw std::runtime_error( ss.str( ) );
				}
				return pEnumerator;
			}
		}	// namespace impl

	}	// namespace wmi
}	// namespace daw
