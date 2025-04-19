// // composables/useApiFetch.ts
// import { $fetch, type FetchOptions } from "ofetch";
// import { useAuthStore } from "~/store/authStore";
// import {
//   navigateTo,
//   useNuxtApp,
//   useRuntimeConfig,
//   useRequestHeaders,
// } from "#imports";
// import type { ProblemDetails, ApiResponse } from "~/types";

// export class ApiError extends Error {
//   public problemDetails: ProblemDetails;
//   public statusCode: number;

//   constructor(problemDetails: ProblemDetails, statusCode: number) {
//     super(problemDetails.title || `API Error: ${statusCode}`);
//     this.name = "ApiError";
//     this.problemDetails = problemDetails;
//     this.statusCode = statusCode;
//   }
// }

// export function useApiFetch() {
//   const authStore = useAuthStore();
//   const config = useRuntimeConfig();
//   const headers = import.meta.server
//     ? useRequestHeaders(["cookie"])
//     : undefined;

//   const getCsrfToken = (): string | undefined => {
//     if (import.meta.client) {
//       const match = document.cookie.match(
//         new RegExp("(^| )CSRF-TOKEN=([^;]+)")
//       );
//       return match ? match[2] : undefined;
//     } else if (import.meta.server && headers?.cookie) {
//       const cookieHeader = headers.cookie;
//       const match = cookieHeader.match(
//         new RegExp("(^|;\\s*)CSRF-TOKEN=([^;]+)")
//       );
//       return match ? match[2] : undefined;
//     }
//     return undefined;
//   };

//   return async function apiFetch<T>(
//     url: string,
//     options: FetchOptions<"json"> = {}
//   ): Promise<ApiResponse<T>> {
//     const defaults: FetchOptions = {
//       baseURL: config.public.apiBaseUrl,
//       headers: {
//         Accept: "application/json",
//         "X-Requested-With": "XMLHttpRequest",
//       },
//       credentials: "include",

//       onRequest({ options }) {
//         const method = options.method?.toUpperCase();
//         if (
//           method &&
//           method !== "GET" &&
//           method !== "HEAD" &&
//           method !== "OPTIONS"
//         ) {
//           const csrfToken = getCsrfToken();
//           if (csrfToken) {
//             options.headers = new Headers(options.headers);
//             options.headers.set("X-CSRF-TOKEN", csrfToken);
//           } else {
//             console.warn("CSRF token missing for state-changing request.");
//           }
//         }
//       },

//       onResponse({ response }) {
//         const body = response._data;
//         if (
//           response.ok &&
//           (typeof body !== "object" || body === null || !("payload" in body))
//         ) {
//           console.warn(
//             `API response for ${response.url} doesn't match ApiResponse<T>.`,
//             body
//           );
//         }
//       },

//       onResponseError({ request, response }) {
//         const statusCode = response.status;
//         const problemDetails = response._data as ProblemDetails;

//         console.error(
//           `API Request Error (${statusCode}) for ${request}:`,
//           problemDetails || response._data
//         );

//         if (statusCode === 401) {
//           console.log("API returned 401, initiating logout...");
//           (async () => {
//             await authStore.logout();
//           })();
//           throw new Error("UnauthorizedRedirect");
//         } else if (
//           problemDetails &&
//           typeof problemDetails === "object" &&
//           problemDetails.title
//         ) {
//           throw new ApiError(problemDetails, statusCode);
//         } else {
//           const message =
//             response._data?.message || "An unexpected API error occurred.";
//           throw new Error(`API Error (${statusCode}): ${message}`);
//         }
//       },
//     };

//     const mergedOptions: FetchOptions<"json", ApiResponse<T>> = {
//       ...defaults,
//       ...options,
//       // Force responseType to be 'json'
//       responseType: "json",
//     };

//     return $fetch<ApiResponse<T>>(url, mergedOptions);
//   };
// }
// composables/useApiFetch.ts
import { $fetch, type FetchOptions } from "ofetch";
import { useAuthStore } from "~/store/authStore";
import { useRuntimeConfig, useRequestHeaders } from "#imports";
import type { ProblemDetails, ApiResponse } from "~/types";

export class ApiError extends Error {
  public problemDetails: ProblemDetails;
  public statusCode: number;

  constructor(problemDetails: ProblemDetails, statusCode: number) {
    super(problemDetails.title || `API Error: ${statusCode}`);
    this.name = "ApiError";
    this.problemDetails = problemDetails;
    this.statusCode = statusCode;
  }
}

export function useApiFetch() {
  const authStore = useAuthStore();
  const config = useRuntimeConfig();
  const headers = import.meta.server
    ? useRequestHeaders(["cookie"])
    : undefined;

  const getCsrfToken = (): string | undefined => {
    if (import.meta.client) {
      const match = document.cookie.match(
        new RegExp("(^| )CSRF-TOKEN=([^;]+)")
      );
      return match ? match[2] : undefined;
    } else if (import.meta.server && headers?.cookie) {
      const cookieHeader = headers.cookie;
      const match = cookieHeader.match(
        new RegExp("(^|;\\s*)CSRF-TOKEN=([^;]+)")
      );
      return match ? match[2] : undefined;
    }
    return undefined;
  };

  return async function apiFetch<T>(
    url: string,
    options: FetchOptions<"json"> = {}
  ): Promise<ApiResponse<T>> {
    const defaults: FetchOptions<"json"> = {
      baseURL: config.public.apiBaseUrl,
      headers: {
        Accept: "application/json",
        "X-Requested-With": "XMLHttpRequest",
      },
      credentials: "include",
      responseType: "json",

      onRequest({ options }) {
        const method = options.method?.toUpperCase();
        if (
          method &&
          method !== "GET" &&
          method !== "HEAD" &&
          method !== "OPTIONS"
        ) {
          const csrfToken = getCsrfToken();
          if (csrfToken) {
            options.headers = new Headers(options.headers);
            options.headers.set("X-CSRF-TOKEN", csrfToken);
          } else {
            console.warn("CSRF token missing for state-changing request.");
          }
        }
      },

      onResponse({ response }) {
        const body = response._data;
        if (
          response.ok &&
          (typeof body !== "object" || body === null || !("payload" in body))
        ) {
          console.warn(
            `API response for ${response.url} doesn't match ApiResponse<T>.`,
            body
          );
        }
      },

      onResponseError({ request, response }) {
        const statusCode = response.status;
        const problemDetails = response._data as ProblemDetails;

        console.error(
          `API Request Error (${statusCode}) for ${request}:`,
          problemDetails || response._data
        );

        if (statusCode === 401) {
          console.log("API returned 401, initiating logout...");
          (async () => {
            await authStore.logout();
          })();
          throw new Error("UnauthorizedRedirect");
        } else if (
          problemDetails &&
          typeof problemDetails === "object" &&
          problemDetails.title
        ) {
          throw new ApiError(problemDetails, statusCode);
        } else {
          const message =
            response._data?.message || "An unexpected API error occurred.";
          throw new Error(`API Error (${statusCode}): ${message}`);
        }
      },
    };

    const mergedOptions: FetchOptions<"json", ApiResponse<T>> = {
      ...defaults,
      ...options,
      responseType: "json", // Force JSON response type
    };

    return $fetch<ApiResponse<T>>(url, mergedOptions);
  };
}
export function useApi() {
  const apiFetch = useApiFetch();

  return {
    get: <T>(url: string, options: FetchOptions<"json"> = {}) =>
      apiFetch<T>(url, { method: "GET", ...options }),
    post: <T>(url: string, data?: any, options: FetchOptions<"json"> = {}) =>
      apiFetch<T>(url, { method: "POST", body: data, ...options }),
    put: <T>(url: string, data?: any, options: FetchOptions<"json"> = {}) =>
      apiFetch<T>(url, { method: "PUT", body: data, ...options }),
    delete: <T>(url: string, options: FetchOptions<"json"> = {}) =>
      apiFetch<T>(url, { method: "DELETE", ...options }),
  };
}
