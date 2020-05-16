package security.gm;

public class StringProcessor 
{
	int space = 27;  // default value is space
	int A = 65;
	int Z = 90;
	
	// Given a string, convert to string to all capital letters!
	public String normalize_str(String s)
	{
	    String valid_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ";
	    String answer = "";
	    for (int i = 0; i < valid_chars.length();i++)
	    {
	    	if(valid_chars.indexOf(s.charAt(i))!=-1)
	    	{
	    		answer += Character.toUpperCase(s.charAt(i));
	    	}
	    }
	    return answer;
	}

	public String int_encode_char(int ind)
	{
	    // ind = ord(c)
		int val = space;

	    // A-Z: A=01, B=02 ... Z=26
	    if (A <= ind && ind <= Z)
	    {
	        val = ind - A + 1;
	    }
	    // "format the integer with 2 digits, left padding it with zeroes"
	    return String.format("%02d", val);
	}

	public int int_encode_str(String s)
	{
		String answer = normalize_str(s);
		for (int i = 0; i < answer.length();i++)
		{
			answer += int_encode_char((int) answer.charAt(i));
		}
		return Integer.parseInt(answer);
	}
}
