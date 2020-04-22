import re

nlreg = re.compile("\r?\n|\r")

def normalizeData(header_values: dict, method: str, path: str, headers: list):
    """ 
    Normalize data before being used in the signature process
  
    This function create an Authorization header with the given value and configuration
  
    Parameters:   
    header_values (dict): A dictionary containing every header and it value  
    method (str): The http method used for the request  
    path (str): The path of the request (without host)  
    headers (list<string>): The list of headers to use in the signature  
  
    Returns: 
    list<str>: List of every normalized headers
  
    """
    if len(headers) == 0:
        raise ValueError("At least one header should be signed")
    result = list()
    for h in headers:
        hl = str.lower(h)
        if hl == '(request-target)':
            result.append({"name":"(request-target)", "values":[str.lower(method) + " " + str.lower(path)]})
        else:
            found = False
            for hv in header_values.keys():
                if str.lower(hv) == hl:
                    if not header_values[hv] == None:
                        found = True
                        if next((x for x in result if x["name"] == hl), None) != None:
                            raise ValueError("Tried to add the same header multiple times")
                        val = header_values[hv]
                        if isinstance(val, list):
                            result.append({"name":hl, "values": [str(a) for a in val]})
                        else:
                            result.append({"name":hl, "values": [str(val)]})
                        break
            if not found:
                raise ValueError("Missing header value for " + h)
    return result

def stringifyNormalizedData(data: list):
    """ 
    Normalize data before being used in the signature process
  
    This function create an Authorization header with the given value and configuration
  
    Parameters:   
    data (list<dict>): The list of normalized headers
  
    Returns: 
    str: All header stringified
  
    """
    components = list()
    for h in data:
        cval = list()
        for val in h["values"]:
            lines = [l.strip() for l in nlreg.split(val)]
            cval.append(' '.join(lines))
        components.append(h["name"] + ": " + ', '.join(cval))
    return '\n'.join(components)