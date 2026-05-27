use super::*;

pub(super) fn submitted_token<'a>(
    headers: &'a HeaderMap,
    header_name: &HeaderName,
) -> Result<&'a str, Error> {
    let Some(value) = single_header_value(headers, header_name, "submitted token")? else {
        return Err(Error::CsrfTokenMissing);
    };
    let token = value
        .to_str()
        .map_err(Error::CsrfSubmittedTokenHeaderDecode)?;
    if token.is_empty() {
        return Err(Error::CsrfTokenMissing);
    }
    Ok(token)
}

pub(super) fn append_set_cookie_header(
    headers: &mut HeaderMap,
    cookie: &Cookie<'_>,
) -> Result<(), Error> {
    let value =
        HeaderValue::from_str(&cookie.to_string()).map_err(Error::CookieSetHeaderInvalid)?;
    headers.append(SET_COOKIE, value);
    Ok(())
}

pub(super) fn header_to_nonempty_str<'a>(
    headers: &'a HeaderMap,
    header_name: &HeaderName,
    label: &'static str,
) -> Result<Option<&'a str>, Error> {
    let Some(value) = single_header_value(headers, header_name, label)? else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|source| Error::CsrfHeaderDecode { label, source })?;
    Ok((!value.is_empty()).then_some(value))
}

fn single_header_value<'a>(
    headers: &'a HeaderMap,
    header_name: &HeaderName,
    label: &'static str,
) -> Result<Option<&'a HeaderValue>, Error> {
    let mut values = headers.get_all(header_name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Error::DuplicateCsrfHeader { label });
    }
    Ok(Some(value))
}
