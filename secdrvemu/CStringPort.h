#ifndef __CSTRINGPORT_H__
#define __CSTRINGPORT_H__

#ifdef _MSC_VER
#pragma warning(disable:4786)
#endif

#include <stdlib.h>
#include <stdarg.h>
#include <string>

using namespace std;

// Would be nice
// int _vscprintf(const char *format, va_list argptr);

// For MinGW/Visual Studio
static int vasprintf (char **result, const char *format, va_list *args)
{
  const char *p = format;
  int total_width = (int)strlen (format) + 1;
  va_list ap;

  memcpy (&ap, args, sizeof (va_list));

  while (*p != '\0')
    {
      if (*p++ == '%')
	{
	  while (strchr ("-+ #0", *p))
	    ++p;
	  if (*p == '*')
	    {
	      ++p;
	      total_width += abs (va_arg (ap, int));
	    }
	  else
	    total_width += strtoul (p, (char **) &p, 10);
	  if (*p == '.')
	    {
	      ++p;
	      if (*p == '*')
		{
		  ++p;
		  total_width += abs (va_arg (ap, int));
		}
	      else
	      total_width += strtoul (p, (char **) &p, 10);
	    }
	  while (strchr ("hlL", *p))
	    ++p;
	  // Should be big enough for any format specifier except %s and floats.  
	  total_width += 30;
	  switch (*p)
	    {
	    case 'd':
	    case 'i':
	    case 'o':
	    case 'u':
	    case 'x':
	    case 'X':
	    case 'c':
	      (void) va_arg (ap, int);
	      break;
	    case 'f':
	    case 'e':
	    case 'E':
	    case 'g':
	    case 'G':
	      (void) va_arg (ap, double);
	      // Since an ieee double can have an exponent of 307, we'll
		 //make the buffer wide enough to cover the gross case. 
	      total_width += 307;
	      break;
	    case 's':
	      total_width += (int)strlen (va_arg (ap, char *));
	      break;
	    case 'p':
	    case 'n':
	      (void) va_arg (ap, char *);
	      break;
	    }
	  p++;
	}
    }
  *result = (char*)malloc (total_width);
  if (*result != NULL)
    return vsprintf(*result, format, *args);
  else
    return 0;
}

class CStringPort
{	
public:
	CStringPort::CStringPort()
	{
	}

	CStringPort::CStringPort(const char *szString)
	{
		if ( szString )
			theString = szString;
	}

	CStringPort::CStringPort(const wchar_t *pString)
	{
		if ( pString )
		{
			size_t outsize = 0;
			size_t len = wcslen(pString);
			char *szString = new char[len+1];
			int a = wcstombs( szString, pString, len+1);
			theString = szString;
			delete szString;
		}
	}

	/////////////////////////////////
	// Statics					   //
	/////////////////////////////////

	static CStringPort CStringPort::IntToCStringPort(int n)
	{
		CStringPort csRet;
		csRet.Format("%d", n);
		return csRet;
	}

	static CStringPort CStringPort::StaticFormat(char* fmt, ...)
	{
		CStringPort csRet;
		
		char *printString = NULL;

		va_list argp;
		va_start(argp, fmt);

		vasprintf(&printString, fmt, &argp);

		va_end(argp);

		csRet = printString;

		delete [] printString;

		return csRet;
	}

	static CStringPort CStringPort::GUIDToCStringPort(GUID guid)
	{
		CStringPort csRet;
		csRet.Format("{%08x-%04x-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}",
					 guid.Data1, guid.Data2, guid.Data3,
					 guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
					 guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
		return csRet;
	}

	/////////////////////////////////
	// Functions				   //
	/////////////////////////////////

	int CStringPort::Replace(int chOld, int chNew)
	{
		int nRet = 0;

		for ( int i = 0; i != theString.size(); i++ )
		{
			if ( theString[i] == chOld )
			{
				theString[i] = chNew;
				nRet++;
			}
		}

		return nRet;
	}

	int CStringPort::Replace(const char* szOld, const char* szNew)
	{
		int nRet = 0;

		for ( size_t j = 0; (j = theString.find(szOld)) != string::npos; )
		{
			theString.replace(j, strlen(szOld), szNew);
		}

		return nRet;
	}

	CStringPort CStringPort::SubStr(int Start, int Count = -1)
	{
		CStringPort csRet;

		int EndPos = Start+Count;
		if ( EndPos > (int)theString.size() || Count == -1 )
			EndPos = (int)theString.size();

		for ( int i = Start; i != EndPos; i++ )
		{
			csRet += theString[i];
		}

		return csRet;
	}

	CStringPort CStringPort::Left(int nCount)
	{
		CStringPort csRet;

		if ( nCount > 0 )
		{
			if ( nCount > (int)theString.size() )
				nCount = (int)theString.size();

			for  ( int i = 0; i != nCount; i++ )
				csRet += theString[i];
		}

		return csRet;
	}

	CStringPort CStringPort::Right(int nCount)
	{
		CStringPort csRet;

		if ( nCount > 0 )
		{
			if ( nCount > (int)theString.size() )
				nCount = (int)theString.size();
				
			for  ( int i = nCount; i != 0; i-- )
				csRet += theString[theString.size()-i];
		}

		return csRet;
	}

	int CStringPort::Find(const char *szFind)
	{
		int nRet = -1;
		char *pPtr = (char*)strstr(theString.c_str(), szFind);
		if ( pPtr )
		{
			nRet = (int)(pPtr - theString.c_str());
		}
		return nRet;
	}

	int CStringPort::Find(int c)
	{
		int nRet = -1;
		for ( int i = 0; i != theString.size(); i++ )
		{
			if ( theString[i] == c )
			{
				nRet = i;
				break;
			}
		}
		return nRet;
	}

	int CStringPort::ReverseFind(int c)
	{
		int nRet = -1;
		for ( int i = (int)(theString.size()-1); i != -1; i-- )
		{
			if ( theString[i] == c )
			{
				nRet = i;
				break;
			}
		}
		return nRet;
	}

	void CStringPort::InsertAt(int nIndex, CStringPort csStr)
	{
		CStringPort csCurrentStr = theString.c_str();

		CStringPort csLeft = csCurrentStr.Left(nIndex);
		CStringPort csRight = csCurrentStr.Right(csCurrentStr.GetLength()-nIndex);

		theString = csLeft + csStr + csRight;
	}

	void CStringPort::SetAt(int nIndex, int c)
	{
		theString[nIndex] = c;
	}

	int CStringPort::GetAt(int nIndex)
	{
		return theString[nIndex];
	}

	CStringPort & CStringPort::MakeLower()
	{
		for ( int i = 0; i != theString.size(); i++ )
			theString[i] = tolower(theString[i]);
		return *this;
	}

	CStringPort & CStringPort::MakeUpper()
	{
		for ( int i = 0; i != theString.size(); i++ )
			theString[i] = toupper(theString[i]);
		return *this;
	}

	int CStringPort::Compare(const char *szText)
	{
		return strcmp(theString.c_str(), szText);
	}

	int CStringPort::CompareNoCase(const char *szText)
	{
		return _stricmp(theString.c_str(), szText);
	}

	CStringPort & CStringPort::Trim()
	{
		CStringPort csTemp;

		int i, nStart = 0, nEnd = 0;
		for ( i = 0; i != theString.size(); i++ )
		{
			if ( theString[i] != ' ' )
			{
				nStart = i;
				break;
			}
		}
		for ( i = (int)theString.size(); i != 0; i-- )
		{
			if ( theString[i-1] != ' ' )
			{
				nEnd = i;
				break;
			}
		}
		for ( i = nStart; i != nEnd; i++ )
		{
			csTemp += (int)theString[i];
		}

		theString = csTemp;
			
		return *this;
	}

	/////////////////////////////////
	// Operators				   //
	/////////////////////////////////

	int operator[](int pos)
	{
		return theString[pos];
	}

	bool operator<(const CStringPort right) const
	{
		return (strcmp(theString.c_str(), right) < 0);
	}

	bool operator==(const CStringPort right) const
	{
		return ( strcmp(theString.c_str(), right) == 0 );
	}

	bool operator!=(const CStringPort right) const
	{
		return ( strcmp(theString.c_str(), right) != 0 );
	}

	bool operator==(const char *szRight) const
	{
		return ( strcmp(theString.c_str(), szRight) == 0 );
	}

	bool operator!=(const char *szRight) const
	{
		return ( strcmp(theString.c_str(), szRight) != 0 );
	}

	operator const char*() const
	{	
		return theString.c_str();
	}

	operator const wchar_t*() const
	{	
		size_t outsize = 0;
		size_t len = theString.size()+1;
		wchar_t *szString = new wchar_t[len];
		mbstowcs(szString, theString.c_str(), len);
		theWideString = szString;
		delete szString;

		return theWideString.c_str();
	}

	CStringPort CStringPort::operator+(const CStringPort& str) const
	{
		string newStr = (const char *)str;
		string newStr2 = theString + newStr;

		return CStringPort(newStr2.c_str());
	}

	const CStringPort& CStringPort::operator+=(CStringPort str)
	{
		string newStr = (const char *)str;
		string newStr2 = theString + newStr;

		theString = newStr2.c_str();

		return *this;
	}

	const CStringPort& CStringPort::operator+=(const char* str)
	{
		string newStr = str;
		string newStr2 = theString + newStr;

		theString = newStr2.c_str();

		return *this;
	}

	const CStringPort& CStringPort::operator+=(int n)
	{
		CStringPort temp;
		temp.Format("%c", (int)n);

		string newStr = (const char *)temp;
		string newStr2 = theString + newStr;

		theString = newStr2.c_str();

		return *this;
	}

	const CStringPort& CStringPort::operator+=(unsigned const char* str)
	{
		string newStr = (const char *)str;
		string newStr2 = theString + newStr;

		theString = newStr2.c_str();

		return *this;
	}

	const CStringPort& CStringPort::operator=(unsigned const char* str)
	{
		string newStr = (const char *)str;
		theString = newStr.c_str();

		return *this;
	}

	void CStringPort::Format(char* fmt, ...)
	{
		char *printString = NULL;

		va_list argp;
		va_start(argp, fmt);

		vasprintf(&printString, fmt, &argp);

		va_end(argp);

		theString = printString;

		delete [] printString;
	}

	void CStringPort::Empty()
	{
		theString = "";
	}

	bool CStringPort::IsEmpty() const
	{
		return theString == "";
	}

	int CStringPort::GetLength()
	{
		return (int)theString.size();
	}

private:
	string theString;
	mutable wstring theWideString;
};

inline CStringPort operator+(const char*& s1, const CStringPort& s2)
{
	string str1 = s1;
	string str2 = (const char *)s2;
	string str3 = str1 + str2;
	
	CStringPort sRet(str3.c_str());

	return sRet;
}

inline CStringPort operator+(const char* s1, const CStringPort& s2)
{
	string str1 = s1;
	string str2 = (const char *)s2;
	string str3 = str1 + str2;
	
	CStringPort sRet(str3.c_str());

	return sRet;
}

inline CStringPort operator+(const CStringPort& s1, const char*& s2)
{
	string str1 = (const char *)s1;
	string str2 = s2;
	string str3 = str1 + str2;
	
	CStringPort sRet(str3.c_str());

	return sRet;
}

///////////////////////////////////////////////////////////////////////////////////////////////
// CStringPortPack - Used to pack strings for sending										 //
///////////////////////////////////////////////////////////////////////////////////////////////

class CStringPortPack
{
public:
	void AddString(CStringPort csNew)
	{
		csNew.Replace('"', '¬');
		m_csPacked += "\"" + csNew + "\"";
	}

	int GetStringCount()
	{
		int nCount = 0;
		const char* pText = m_csPacked;

		for ( int i = 0; i != m_csPacked.GetLength(); i++ )
		{
			if ( pText[i] == '"' )
				nCount++;
		}

		return nCount/2;
	}

	CStringPort GetString(int nIndex)
	{
		CStringPort csString;
		int nCount = 0;
		const char *pText = m_csPacked;

		for ( int i = 0; i != m_csPacked.GetLength(); i++ )
		{ 
			if ( nCount == nIndex*2 )
			{
				// Skip quotation
				// Find next Quotation
				char *szText;
				int nLen;
				
				// Get Size of String
				nLen = (int)(strchr(&pText[i+1], '"')-&pText[i+1]);

				// Create temporary buffer and copy text
				szText = new char[nLen+10];
				memset(szText, 0, nLen+10);
				strncpy(szText, &pText[i+1], nLen);

				// Copy to CString
				csString = szText;

				// Free and Break;
				delete [] szText;
				break;
			}

			if ( pText[i] == '"' )
				nCount++;
		}

		csString.Replace('¬', '"');

		return csString;
	}

	void SetPackedString(CStringPort csStr)
	{
		m_csPacked = csStr;
	}

	CStringPort GetPackedString()
	{
		return m_csPacked;
	}

	void ResetPackedString()
	{
		m_csPacked.Empty();
	}

private:
	CStringPort m_csPacked;
};

#endif


