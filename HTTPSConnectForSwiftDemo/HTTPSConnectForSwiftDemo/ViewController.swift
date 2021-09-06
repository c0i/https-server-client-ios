//
//  ViewController.swift
//  HTTPSConnectForSwiftDemo
//
//  Created by user on 15/10/10.
//  Copyright © 2015年 BG. All rights reserved.
//

import UIKit

class ViewController: UIViewController, URLSessionDataDelegate {
    var trustedCertArr: NSArray?
    override func viewDidLoad() {
        super.viewDidLoad()
        //导入客户端证书
        let cerPath = Bundle.main.path(forResource: "ca", ofType: "der")
        if let filePath = cerPath {
            let data = NSData(contentsOfFile: filePath)
            let certificate = SecCertificateCreateWithData(nil, data!)
            trustedCertArr = [certificate!]
            
            //发送请求
            let testUrl = NSURL(string: "https://localhost:443")
            let session = Foundation.URLSession(configuration: URLSessionConfiguration.default, delegate: self, delegateQueue: OperationQueue.main)
            let task = session.dataTask(with: NSURLRequest(url: testUrl! as URL) as URLRequest)
            task.resume()
        }
        
        // Do any additional setup after loading the view, typically from a nib.
    }
    
    func urlSession(_ session: URLSession,
                        task: URLSessionTask,
                  didReceive challenge: URLAuthenticationChallenge,
           completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void)
    {
//    //MARK: - NSURLSessionDelegate
//    func URLSession(session: URLSession, didReceiveChallenge challenge: URLAuthenticationChallenge, completionHandler: (URLSession.AuthChallengeDisposition, URLCredential?) -> Void)
//    {
        var err: OSStatus
        var disposition : URLSession.AuthChallengeDisposition = Foundation.URLSession.AuthChallengeDisposition.performDefaultHandling
        
        var trustResult:SecTrustResultType = SecTrustResultType.invalid
        var credential : URLCredential? = nil
        
        //获取服务器的trust object
        let serverTrust: SecTrust = challenge.protectionSpace.serverTrust!
        
        //将读取的证书设置为serverTrust的根证书
        err = SecTrustSetAnchorCertificates(serverTrust, self.trustedCertArr!)
        
        if(err == noErr){
            //通过本地导入的证书来验证服务器的证书是否可信，如果将SecTrustSetAnchorCertificatesOnly设置为NO，则只要通过本地或者系统证书链任何一方认证就行
            err = SecTrustEvaluate(serverTrust, &trustResult)
        }
        
        if(err == errSecSuccess && (trustResult == SecTrustResultType.proceed || trustResult == SecTrustResultType.unspecified)){
            //认证成功，则创建一个凭证返回给服务器
            disposition = Foundation.URLSession.AuthChallengeDisposition.useCredential
            credential = URLCredential(trust: serverTrust)
        }
        else{
            disposition = Foundation.URLSession.AuthChallengeDisposition.cancelAuthenticationChallenge
        }
        
        //回调凭证，传递给服务器
        completionHandler(disposition, credential)
    }
    
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data)
    {
        print(data);
    }
    
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?)
    {
        if (error != nil) {
            print(error);
        }
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

