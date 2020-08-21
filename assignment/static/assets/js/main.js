const rootUrl = 'http://100.25.139.92:5000';

//Default values for Ajax requests
$.ajaxSetup({
    contentType: "application/json; charset=utf-8",
    dataType: "json",
    xhrFields: {withCredentials: true}
})

// This is a wrapper for ajaxRequest
async function ajaxRequest(url, method, data, multipart){
     //Create an request object that contains url, method and data
     let request = {
        url,
        method,
        data: JSON.stringify(data)
    }
    try{
        var response = await $.ajax(request)
    } catch(e) {
        if(e.status === 500){
          
        }
        throw e
    }
        
    return response
    //need to figure out how to handle out invalid token (either token expire or unauthorized)
}