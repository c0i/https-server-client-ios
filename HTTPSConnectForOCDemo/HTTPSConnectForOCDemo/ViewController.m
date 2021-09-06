//
//  ViewController.m
//  HTTPSConnectForOCDemo
//
//  Created by user on 15/10/10.
//  Copyright © 2015年 BG. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()<NSURLSessionDataDelegate>
@property (nonatomic, strong) NSArray *trustedCerArr;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    //
    NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"ca" ofType:@"der"];
    NSData *data = [NSData dataWithContentsOfFile:cerPath];
    SecCertificateRef certificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef) data);
    self.trustedCerArr = @[(__bridge_transfer id)certificate];
    
    //
    NSString *url = nil;
    url = @"https://localhost:443";
    
    NSURL *testURL = [NSURL URLWithString:url];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration] delegate:self delegateQueue:[NSOperationQueue mainQueue]];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:[NSURLRequest requestWithURL:testURL]];
    [task resume];
    // Do any additional setup after loading the view, typically from a nib.
}

static BOOL evaluateTrust(SecTrustRef trust) {
    OSStatus            err;
    SecTrustResultType  result;

    err = SecTrustEvaluate(trust, &result);
    return (err == errSecSuccess) && ( (result == kSecTrustResultProceed) || (result == kSecTrustResultUnspecified) );
}

#pragma mark - NSURLSessionDelegate
- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * __nullable credential))completionHandler
{

    NSLog(@"challenge %@", challenge.protectionSpace.authenticationMethod);
    NSLog(@">>%@", challenge.protectionSpace.host);

    if (challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust) {
        // create trust from protection space
        SecTrustRef trustRef;
        int trustCertificateCount = SecTrustGetCertificateCount(challenge.protectionSpace.serverTrust);

        NSMutableArray* trustCertificates = [[NSMutableArray alloc] initWithCapacity:trustCertificateCount];
        for (int i = 0; i < trustCertificateCount; i++) {
            SecCertificateRef trustCertificate =  SecTrustGetCertificateAtIndex(challenge.protectionSpace.serverTrust, i);
            [trustCertificates addObject:(__bridge id _Nonnull)(trustCertificate)];
        }

        // set evaluation policy
        SecPolicyRef policyRef;
        // set to YES to verify certificate extendedKeyUsage is set to serverAuth
        policyRef = SecPolicyCreateSSL(YES, (CFStringRef) challenge.protectionSpace.host);
//        policyRef = SecPolicyCreateBasicX509();
//        SecTrustSetPolicies(trustRef, policyRef);
        SecTrustCreateWithCertificates((CFArrayRef) trustCertificates, policyRef, &trustRef);

//        [trustCertificates release];

        // load known certificates from keychain and set as anchor certificates
        NSMutableDictionary* secItemCopyCertificatesParams = [[NSMutableDictionary alloc] init];
        [secItemCopyCertificatesParams setObject:(id)kSecClassCertificate forKey:(id)kSecClass];
        [secItemCopyCertificatesParams setObject:@"Server_Cert_Label" forKey:(id)kSecAttrLabel];
        [secItemCopyCertificatesParams setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnRef];
        [secItemCopyCertificatesParams setObject:(id)kSecMatchLimitAll forKey:(id)kSecMatchLimit];

        CFArrayRef certificates;
        certificates = nil;
        SecItemCopyMatching((CFDictionaryRef) secItemCopyCertificatesParams, (CFTypeRef*) &certificates);

        if (certificates != nil && CFGetTypeID(certificates) == CFArrayGetTypeID()) {
            SecTrustSetAnchorCertificates(trustRef, certificates);
            SecTrustSetAnchorCertificatesOnly(trustRef, NO);
        } else {
            // set empty array as own anchor certificate so system anchos certificates are used too!
            SecTrustSetAnchorCertificates(trustRef, (__bridge CFArrayRef)self.trustedCerArr);
            SecTrustSetAnchorCertificatesOnly(trustRef, NO);
        }

        SecTrustResultType result;
        OSStatus trustEvalStatus = SecTrustEvaluate(trustRef, &result);
        if (trustEvalStatus == errSecSuccess) {
            if (result == kSecTrustResultConfirm || result == kSecTrustResultProceed || result == kSecTrustResultUnspecified)
            {
                
                NSLog(@"YESYESYES");
                
                // evaluation OK
                [challenge.sender useCredential:[NSURLCredential credentialForTrust: challenge.protectionSpace.serverTrust] forAuthenticationChallenge:challenge];
                
                
            }
            else {
                NSLog(@"NONONONO");
                
                // evaluation failed
                // ask user to add certificate to keychain
                
                NSArray * trustProperties = (__bridge NSArray*) SecTrustCopyProperties(trustRef);
                NSLog(@"trust properties:%@", trustProperties);
                
                NSDictionary * trustDict = (__bridge NSDictionary*) SecTrustCopyResult(trustRef);
                NSLog(@"dict: %@", trustDict);
            }
        }
        else {
            // evaluation failed - cancel authentication
            [[challenge sender] cancelAuthenticationChallenge:challenge];
        }
    }

    
//        // create trust from protection space
//        SecTrustRef trustRef;
//        int trustCertificateCount = SecTrustGetCertificateCount(challenge.protectionSpace.serverTrust);
//
//        NSMutableArray* trustCertificates = [[NSMutableArray alloc] initWithCapacity:trustCertificateCount];
//        for (int i = 0; i < trustCertificateCount; i++) {
//            SecCertificateRef trustCertificate =  SecTrustGetCertificateAtIndex(challenge.protectionSpace.serverTrust, i);
//            [trustCertificates addObject:(id)trustCertificate];
//        }
////        [trustCertificates addObject:<#(nonnull id)#>];
//
//        // set evaluation policy
//        SecPolicyRef policyRef;
//        // set to YES to verify certificate extendedKeyUsage is set to serverAuth
//        policyRef = SecPolicyCreateSSL(YES, (CFStringRef) challenge.protectionSpace.host);
//        SecTrustCreateWithCertificates((CFArrayRef) trustCertificates, policyRef, &trustRef);
//
////        [trustCertificates release];
//
//        // load known certificates from keychain and set as anchor certificates
//        NSMutableDictionary* secItemCopyCertificatesParams = [[NSMutableDictionary alloc] init];
//        [secItemCopyCertificatesParams setObject:(id)kSecClassCertificate forKey:(id)kSecClass];
//        [secItemCopyCertificatesParams setObject:@"Server_Cert_Label" forKey:(id)kSecAttrLabel];
//        [secItemCopyCertificatesParams setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnRef];
//        [secItemCopyCertificatesParams setObject:(id)kSecMatchLimitAll forKey:(id)kSecMatchLimit];
//
//        CFArrayRef certificates;
//        certificates = nil;
//        SecItemCopyMatching((CFDictionaryRef) secItemCopyCertificatesParams, (CFTypeRef*) &certificates);
//
//        if (certificates != nil && CFGetTypeID(certificates) == CFArrayGetTypeID()) {
//            SecTrustSetAnchorCertificates(trustRef, certificates);
//            SecTrustSetAnchorCertificatesOnly(trustRef, NO);
//        } else {
//            // set empty array as own anchor certificate so system anchos certificates are used too!
//            SecTrustSetAnchorCertificates(trustRef, (CFArrayRef) [NSArray array]);
//            SecTrustSetAnchorCertificatesOnly(trustRef, NO);
//        }
//
//        SecTrustResultType result;
//        OSStatus trustEvalStatus = SecTrustEvaluate(trustRef, &result);
//        if (trustEvalStatus == errSecSuccess) {
//            if (result == kSecTrustResultConfirm || result == kSecTrustResultProceed || result == kSecTrustResultUnspecified) {
//                // evaluation OK
//                [challenge.sender useCredential:[NSURLCredential credentialForTrust: challenge.protectionSpace.serverTrust] forAuthenticationChallenge:challenge];
//            }
//            else {
//                // evaluation failed
//                // ask user to add certificate to keychain
//            }
//        }
//        else {
//            // evaluation failed - cancel authentication
//            [[challenge sender] cancelAuthenticationChallenge:challenge];
//        }
//    }
    
//     if ([challenge.protectionSpace.authenticationMethod isEqual:NSURLAuthenticationMethodServerTrust]) {
//        OSStatus err;
//        NSURLSessionAuthChallengeDisposition disposition = NSURLSessionAuthChallengePerformDefaultHandling;
//        SecTrustResultType  trustResult = kSecTrustResultInvalid;
//        NSURLCredential *credential = nil;
//
//        //获取服务器的trust object
//        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
//
//        //将读取的证书设置为serverTrust的根证书
//        err = SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)self.trustedCerArr);
//        SecTrustSetAnchorCertificatesOnly(serverTrust, false);
//
//
//        if(err == noErr) {
//            //通过本地导入的证书来验证服务器的证书是否可信，如果将SecTrustSetAnchorCertificatesOnly设置为NO，则只要通过本地或者系统证书链任何一方认证就行
//            err = SecTrustEvaluate(serverTrust, &trustResult);
//        }
//
//        if (trustResult == kSecTrustResultRecoverableTrustFailure)
//        {
//
//            {
//                BOOL            allow;
//                OSStatus        err;
//                SecPolicyRef    policy;
//
//                policy = SecPolicyCreateSSL(true, CFSTR("xxxxxxx.com"));
//                err = SecTrustSetPolicies(serverTrust, policy);
//                if (err == errSecSuccess) {
//                   allow = evaluateTrust(serverTrust);
//                }
//
//                CFRelease(policy);
//            }
//
//
//            NSArray * trustProperties = (__bridge NSArray*) SecTrustCopyProperties(serverTrust);
//            NSLog(@"trust properties:%@", trustProperties);
//
//            NSDictionary * trustDict = (__bridge NSDictionary*) SecTrustCopyResult(serverTrust);
//            NSLog(@"dict: %@", trustDict);
//        }
//
//        if (err == errSecSuccess && (trustResult == kSecTrustResultProceed || trustResult == kSecTrustResultUnspecified)){
//            //认证成功，则创建一个凭证返回给服务器
//            disposition = NSURLSessionAuthChallengeUseCredential;
//            credential = [NSURLCredential credentialForTrust:serverTrust];
//        }
//        else{
//            disposition = NSURLSessionAuthChallengeCancelAuthenticationChallenge;
//        }
//
//        //回调凭证，传递给服务器
//        if(completionHandler){
//            completionHandler(disposition, credential);
//        }
//
//     }
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data{
    NSDictionary *result = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:nil];
    NSLog(@"%@", result);
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
didCompleteWithError:(nullable NSError *)error{
    if(error){
        NSLog(@"%@", error);
    }
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
