//
//  OAuth2SplitSwift.swift
//  OAuthSwift
//
//  Created by Sander Nieuwenhuizen on 21/12/2016.
//
//
import Foundation

open class OAuth2SplitSwift: OAuthSwift {

  // If your oauth provider need to use basic authentification
  // set value to true (default: false)
  open var accessTokenBasicAuthentification = false

  // Set to true to deactivate state check. Be careful of CSRF
  open var allowMissingStateCheck: Bool = false

  var consumerKey: String
  var authorizeUrl: String
  var responseType: String
  var contentType: String?

  // MARK: init
  public convenience init(consumerKey: String, authorizeUrl: String, responseType: String, contentType: String){
    self.init(consumerKey: consumerKey, authorizeUrl: authorizeUrl, responseType: responseType)
    self.contentType = contentType
  }

  public init(consumerKey: String, authorizeUrl: String, responseType: String){
    self.consumerKey = consumerKey
    self.authorizeUrl = authorizeUrl
    self.responseType = responseType
    super.init(consumerKey: consumerKey, consumerSecret: "")
    self.client.credential.version = .oauth2
  }

  public convenience init?(parameters: ConfigParameters){
    guard let consumerKey = parameters["consumerKey"], let responseType = parameters["responseType"], let authorizeUrl = parameters["authorizeUrl"] else {
      return nil
    }

    self.init(consumerKey:consumerKey, authorizeUrl: authorizeUrl, responseType: responseType)
  }

  open var parameters: ConfigParameters {
    return [
      "consumerKey": consumerKey,
      "authorizeUrl": authorizeUrl,
      "responseType": responseType
    ]
  }

  // MARK: functions
  @discardableResult
  open func authorize(withCallbackURL callbackURL: URL, scope: String, state: String, parameters: Parameters = [:], headers: OAuthSwift.Headers? = nil, success: @escaping SplitSuccessHandler, failure: FailureHandler?)  -> OAuthSwiftRequestHandle? {

    self.observeCallback { url in
      var responseParameters = [String: String]()
      if let query = url.query {
        responseParameters += query.parametersFromQueryString
      }
      if let fragment = url.fragment , !fragment.isEmpty {
        responseParameters += fragment.parametersFromQueryString
      }

      if let status = responseParameters["status"] {
        switch status {
          case "ok":
            print("done!")
            success(responseParameters)
          case "error":
            print("error")
            let description = responseParameters["error_description"] ?? ""
            let message = NSLocalizedString(status, comment: description)
            failure?(OAuthSwiftError.serverError(message: message))
          default:
            print("other status, weird: \(status)")
            success(responseParameters)
        }
      } else {
        // do something fancy
      }
    }

    var queryString = "client_id=\(self.consumerKey)"
    queryString += "&redirect_uri=\(callbackURL.absoluteString.urlEncodedString)"
    queryString += "&response_type=\(self.responseType)"
    if !scope.isEmpty {
      queryString += "&scope=\(scope.urlEncodedString)"
    }
    if !state.isEmpty {
      queryString += "&state=\(state.urlEncodedString)"
    }
    for param in parameters {
      queryString += "&" + "\(param.0)".urlEncodedString + "=" + "\(param.1)".urlEncodedString
    }

    var urlString = self.authorizeUrl
    urlString += (self.authorizeUrl.contains("?") ? "&" : "?")

    if let queryURL = URL(string: urlString + queryString) {
      self.authorizeURLHandler.handle(queryURL)
      return self
    }
    else {
      self.cancel() // ie. remove the observer.
      failure?(OAuthSwiftError.encodingError(urlString: urlString))
      return nil
    }
  }

  @discardableResult
  open func authorize(withCallbackURL urlString: String, scope: String, state: String, parameters: Parameters = [:], headers: OAuthSwift.Headers? = nil, success: @escaping SplitSuccessHandler, failure: FailureHandler?) -> OAuthSwiftRequestHandle? {
    guard let url = URL(string: urlString) else {
      failure?(OAuthSwiftError.encodingError(urlString: urlString))
      return nil
    }
    return authorize(withCallbackURL: url, scope: scope, state: state, parameters: parameters, headers: headers, success: success, failure: failure)
  }

}

