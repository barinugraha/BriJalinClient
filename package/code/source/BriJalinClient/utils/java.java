package BriJalinClient.utils;

// -----( IS Java Code Template v1.2

import com.wm.data.*;
import com.wm.util.Values;
import com.wm.app.b2b.server.Service;
import com.wm.app.b2b.server.ServiceException;
// --- <<IS-START-IMPORTS>> ---
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.security.PrivateKey;
// --- <<IS-END-IMPORTS>> ---

public final class java

{
	// ---( internal utility methods )---

	final static java _instance = new java();

	static java _newInstance() { return new java(); }

	static java _cast(Object o) { return (java)o; }

	// ---( server methods )---




	public static final void OAuthSignature (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(OAuthSignature)>> ---
		// @sigtype java 3.5
		// [i] field:0:required clientId
		// [i] field:0:required timestampRequest
		// [i] field:0:required algorithm
		// [i] object:0:required privateKey
		// [o] field:0:required signature
		// pipeline
		IDataCursor pipelineCursor = pipeline.getCursor();
		
		//populate required data
		RSAPrivateKey privateKey = (RSAPrivateKey) IDataUtil.get(pipelineCursor, "privateKey");
		String timestampRequest = IDataUtil.getString( pipelineCursor, "timestampRequest" );
		String clientId = IDataUtil.getString( pipelineCursor, "clientId" );
		
		logMessageToServerLog(pipeline, "timestampRequest = " + timestampRequest);
		logMessageToServerLog(pipeline, "clientId = " + clientId);
		
		pipelineCursor.destroy();
		
		String data = clientId+"|"+timestampRequest;
		logMessageToServerLog(pipeline, "data = " + data);
		
		String signature = "";
		
		try {
			
			//create signature
			signature = sign(privateKey, data);
			logMessageToServerLog(pipeline, "signature = " + signature);
			
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		
		IDataCursor pipelineCursorOut = pipeline.getCursor();
		IDataUtil.put( pipelineCursorOut, "signature", signature );
		pipelineCursorOut.destroy();
		// --- <<IS-END>> ---

                
	}

	// --- <<IS-START-SHARED>> ---
	
	public static String sign(RSAPrivateKey privateKey, String data) {
		
		String signature = null;
	
		try {
			Signature sign = Signature.getInstance("SHA256withRSA");
			sign.initSign(privateKey);
			byte[] byteMessage = data.getBytes();
	
			sign.update(byteMessage, 0, byteMessage.length);
			byte[] byteSignature = sign.sign();
	
			signature = new String(Base64.getEncoder().encode(byteSignature));
			
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return signature;
	}
	
	public static void logMessageToServerLog(
			IData pipeline, 
		    String message) throws ServiceException{
		logMessageToServerLog(pipeline,"[OAuthSignature] "+message,null,null);
	}
	
	public static void logMessageToServerLog(
		    IData pipeline, 
		    String message, 
		    String function, 
		    String level) 
		    throws ServiceException 
		{ 
		    IDataCursor inputCursor = pipeline.getCursor(); 
		    IDataUtil.put(inputCursor, "message", message); 
		    IDataUtil.put(inputCursor, "function", function); 
		    IDataUtil.put(inputCursor, "level", level); 
		    inputCursor.destroy();
	
		    try
		    {
		        Service.doInvoke("pub.flow", "debugLog", pipeline);
		    }
		    catch (Exception e)
		    {
		        throw new ServiceException(e.getMessage());
		    }
		}
		
	// --- <<IS-END-SHARED>> ---
}

