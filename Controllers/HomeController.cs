using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace WebApplication2.Controllers
{
	public class HomeController : Controller
	{
		public ActionResult Index()
		{
			return View();
		}

		public ActionResult About()
		{
			ViewBag.Message = "Your application description page.";

			return View();
		}

		public ActionResult Contact()
		{
			ViewBag.Message = "Your contact page.";

			return View();
		}

		[MyAuth]
		public ActionResult TestAuth()
		{
			return View();
		}
	}

	public class MyAuthAttribute : AuthorizeAttribute
	{
		public override void OnAuthorization(AuthorizationContext filterContext)
		{
			var user = filterContext.HttpContext.User;
			var authenticationManager = filterContext.HttpContext.Request.GetOwinContext().Authentication;
			var owinUser = authenticationManager.User;
			base.OnAuthorization(filterContext);
		}
	}
}