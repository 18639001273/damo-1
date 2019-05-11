package com.action;
/**
 * Administrator login, add modification, delete login log
 Permission check
 */
import java.io.IOException;
import java.util.List;
import java.util.StringTokenizer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.struts.taglib.html.RewriteTag;

import com.bean.AdminBean;
import com.bean.PermissionBean;
import com.bean.RoleBean;
import com.bean.SystemBean;
import com.util.Constant;
import com.util.MD5;

public class AdminAction extends HttpServlet {

	/**
	 * Constructor of the object.
	 */
	public AdminAction() {
		super();
	}

	/**
	 * Destruction of the servlet. <br>
	 */
	public void destroy() {
		super.destroy(); // Just puts "destroy" string in log
		// Put your code here
	}

	/**
	 * The doGet method of the servlet. <br>
	 *
	 * This method is called when a form has its tag value method equals to get.
	 * 
	 * @param request the request send by the client to the server
	 * @param response the response send by the server to the client
	 * @throws ServletException if an error occurred
	 * @throws IOException if an error occurred
	 */
	public void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		doPost(request,response);
	}

	/**
	 * The doPost method of the servlet. <br>
	 *
	 * This method is called when a form has its tag value method equals to post.
	 * 
	 * @param request the request send by the client to the server
	 * @param response the response send by the server to the client
	 * @throws ServletException if an error occurred
	 * @throws IOException if an error occurred
	 */
	public void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		response.setContentType(Constant.CONTENTTYPE);
		request.setCharacterEncoding(Constant.CHARACTERENCODING);
		try{
			String method=request.getParameter("method").trim();
			AdminBean loginbean = new AdminBean();
			HttpSession session = request.getSession();
			session.setMaxInactiveInterval(1200);
			SystemBean systembean = new SystemBean();
			String sysdir = systembean.getDir();
			if(method.equals("one")){//adminSign in
				String username = request.getParameter("username");
				String password = request.getParameter("password");
				if(username == null||username.trim().equals("")){
					request.setAttribute("message", "Please enter the user name correctly£¡");
					request.getRequestDispatcher(sysdir+"/login.jsp").forward(request, response);
				}
				else if(password == null||password.trim().equals("")){
					request.setAttribute("message", "Please input a password£¡");
					request.getRequestDispatcher(sysdir+"/login.jsp").forward(request, response);
				}
				else{
					String md5password = MD5.MD5(password);
					String agent = request.getHeader("user-agent"); 
					StringTokenizer st = new StringTokenizer(agent,";"); 
					String useros=st.nextToken();
					String loginip = request.getRemoteAddr();			
					int flag = loginbean.adminLogin(username,md5password, password,useros,loginip);
					switch (flag){
						case Constant.SUCCESS:
							List list = loginbean.getAdminInfo(username);
							session.setAttribute("user", username);
							session.setAttribute("list", list);
							request.getRequestDispatcher(sysdir+"/").forward(request, response);
							break;
						case Constant.NAME_ERROR:
							request.setAttribute("message", "User name error! Please confirm administrative permissions£¡");
							request.getRequestDispatcher(sysdir+"/login.jsp").forward(request, response);
							break;
						case Constant.PASSWORD_ERROR:
							request.setAttribute("message", "Password error, please confirm administrative permissions£¡");
							request.getRequestDispatcher(sysdir+"/login.jsp").forward(request, response);
							break;
					}
				}
			}
			else if(method.equals("editpwd")){//admin edit password
				String username2 = (String)session.getAttribute("user");
				if(username2 == null){
					request.getRequestDispatcher("error.jsp").forward(request, response);
				}
				else{
					String oldpwd = MD5.MD5(request.getParameter("oldpwd").trim());
					String newpwd = MD5.MD5(request.getParameter("newpwd").trim());
					String username = (String)session.getAttribute("user");
					int flag = loginbean.editPassword(username, oldpwd, newpwd);
					switch (flag){
						case Constant.SUCCESS:
							request.setAttribute("message", "Successful password modification£¡");
							request.getRequestDispatcher(sysdir+"/system/editpwd.jsp").forward(request, response);
							break;
						case Constant.PASSWORD_ERROR:
							request.setAttribute("message", "The original password is incorrect. Please confirm permissions.£¡");
							request.getRequestDispatcher(sysdir+"/system/editpwd.jsp").forward(request, response);
							break;
						case Constant.SYSTEM_ERROR:
							request.setAttribute("message", "System maintenance, please try again later£¡");
							request.getRequestDispatcher(sysdir+"/system/editpwd.jsp").forward(request, response);
							break;
					}
				}		
			}
			else if(method.equals("adminManager")){
				//Administrator User Management
				//Must be super tube to use
				
				String username2 = (String)session.getAttribute("user");
				RoleBean roleBean=new RoleBean();
				int flag=roleBean.selectRoleByUsername(username2);
				if(flag==1)
				{
					System.out.println("Currently supertube");
					String username = (String)session.getAttribute("user");
					AdminBean adminBean=new AdminBean();
					AdminBean[] adlist=adminBean.getAll();
//					System.out.println(adlist);
					/*
					for(AdminBean ad:adlist)
					{
					System.out.println(ad.toString());	
						
					}
					*/
					for(AdminBean ad:adlist)
					{
					
					RoleBean roleBean1=new RoleBean();
					roleBean1=roleBean1.getRoleNameByUsername(ad.getUsername());
			        ad.setDescription(roleBean1.getDescription());
			        ad.setName(roleBean1.getName());
					}
					
					request.setAttribute("adminList", adlist);
	                

					request.getRequestDispatcher("/admin/member/person2.jsp").forward(request, response);
					
				}
				else
				{
                
			    request.setAttribute("message", "Only over-managed permissions can be used. Please confirm permissions.£¡");

				request.getRequestDispatcher("error2.jsp").forward(request, response);
				}
				
				
				
				
				
			}
			//Website bulletin management
			///affiche/index.jsp
			else if(method.equals("affiche"))
			{
				//Check authority
				String username2 = (String)session.getAttribute("user");
				PermissionBean pb=new PermissionBean();
				int flag=pb.checkaffiche("affiche");
				RoleBean roleBean=new RoleBean();
				int flag2=roleBean.selectRoleByUsername(username2);
				if(flag==1||flag2==1)
				{
				request.getRequestDispatcher("/admin/affiche/index.jsp").forward(request, response);
				}
				else
				{
					
					request.setAttribute("message", "Only over-managed permissions can be used. Please confirm permissions.£¡");
					request.getRequestDispatcher("error2.jsp").forward(request, response);
					
				}
			}
			
			
			
			//Complaint management
			//<%=basePath %><%=dir %>/guestbook/index.jsp
			else if(method.equals("guestbook"))
			{
				//Check authority
				String username2 = (String)session.getAttribute("user");

				PermissionBean pb=new PermissionBean();
				int flag=pb.checkaffiche("guestbook");
				RoleBean roleBean=new RoleBean();
				int flag2=roleBean.selectRoleByUsername(username2);
				if(flag==1||flag2==1)
				{
				request.getRequestDispatcher("/admin/guestbook/index.jsp").forward(request, response);
				}
				else
				{
					
					request.setAttribute("message", "Only over-managed permissions can be used. Please confirm permissions.£¡");
					request.getRequestDispatcher("error2.jsp").forward(request, response);
					
				}
			
			}
			
			//user management
			//<%=dir %>/member/person.jsp
			else if(method.equals("user"))
			{
				//Check authority
				String username2 = (String)session.getAttribute("user");
				PermissionBean pb=new PermissionBean();
				int flag=pb.checkaffiche("user");
				RoleBean roleBean=new RoleBean();
				int flag2=roleBean.selectRoleByUsername(username2);

				if(flag==1||flag2==1)
				{
				request.getRequestDispatcher("/admin/member/person.jsp").forward(request, response);
				}
				else
				{
					
					request.setAttribute("message", "Only over-managed permissions can be used. Please confirm permissions£¡");
					request.getRequestDispatcher("error2.jsp").forward(request, response);
					
				}
			
			}
			else if(method.equals("delete"))
			{
				String username2 = (String)session.getAttribute("user");
				int id =Integer.parseInt(request.getParameter("id"));
				RoleBean roleBean=new RoleBean();
				int flag=roleBean.selectRoleByUsername(username2);
				if(flag==1)
				{
					
					AdminBean ad=new AdminBean();
					ad.delManager(id);
					request.setAttribute("message", "Delete successful");
					request.getRequestDispatcher("/Admin.do?method=adminManager").forward(request, response);

				}
				else
				{
					request.setAttribute("message", "Only over-managed permissions can be used. Please confirm permissions£¡");
					request.getRequestDispatcher("error2.jsp").forward(request, response);
					
					
				}
				
				
				
				
				
			}
			else if(method.equals("role"))
			{
				String username2 = (String)session.getAttribute("user");
				RoleBean roleBean=new RoleBean();
				int flag=roleBean.selectRoleByUsername(username2);
				if(flag==1)
				{
					PermissionBean pb=new PermissionBean();
					PermissionBean[] pblist=pb.getAll();
					request.setAttribute("pblist", pblist);
					
					
				request.getRequestDispatcher("/admin/member/role.jsp").forward(request, response);
				}
				else
				{
					request.setAttribute("message", "Only over-managed permissions can be used. Please confirm permissions£¡");
					request.getRequestDispatcher("error2.jsp").forward(request, response);
					
					
				}
			}
//			roleManager
			else if(method.equals("roleManager")){
				
				
				String username2 = (String)session.getAttribute("user");
				RoleBean roleBean=new RoleBean();
				int flag=roleBean.selectRoleByUsername(username2);
				
				if(flag==1)
				{
//					System.out.println("Currently supertube");
					String affiche=request.getParameter("affiche");
					String expressage=request.getParameter("expressage");
					String user=request.getParameter("user");
					String guestbook=request.getParameter("guestbook");
                    if(affiche!=null)
                    {
                    	roleBean.update(affiche);              	                    	
                    }
                    else
                    {
                    	roleBean.rupdate("affiche");              	                    	

                    }
                    if(expressage!=null)
                    {
                    	roleBean.update(expressage);              	                    	
                    }
                    else
                    {
                    	roleBean.rupdate("expressage");              	                    	
                    }
                    if(user!=null)
                    {
                    	roleBean.update(user);              	                    	
                    }
                    else
                    {
                    	roleBean.rupdate("user");              	                    	
                    }
					
                    if(guestbook!=null)
                    {
                    	roleBean.update(guestbook);              	                    	
                    }
                    else
                    {
                    	roleBean.rupdate("guestbook");              	                    	
                    }
					
					
					
					//Update to database
					
					
					
					request.setAttribute("message", "Submit successfully");
					request.getRequestDispatcher("./Admin.do?method=role").forward(request, response);

					
				}
				else
				{
                
			    request.setAttribute("message", "Only over-managed permissions can be used. Please confirm permissions£¡");
				request.getRequestDispatcher("error2.jsp").forward(request, response);
				}
				
				
				
				
			}
			else if(method.equals("exit")){//admin exit
				String username2 = (String)session.getAttribute("user");
				if(username2 == null){
					request.getRequestDispatcher("error.jsp").forward(request, response);
				}
				else{
					session.removeAttribute("user");
					session.removeAttribute("list");
					System.gc();
					request.getRequestDispatcher(sysdir+"/login.jsp").forward(request, response);
				}			
			}
			else if(method.equals("manager")){//add,update manager
				String username2 = (String)session.getAttribute("user");
				if(username2 == null){
					request.getRequestDispatcher("error.jsp").forward(request, response);
				}
				else{
					
						String username = request.getParameter("username").trim();
						String password = MD5.MD5(request.getParameter("password").trim());
						
						String fd =  request.getParameter("fd");
						int flag = loginbean.addManager(username, password, fd, "1");
						if(flag == Constant.SUCCESS){
							request.setAttribute("message", "Increase Administrator Success£¡");
							request.getRequestDispatcher(sysdir+"/system/user.jsp").forward(request, response);
						}
						else if(flag == Constant.SAME_NAME){
							request.setAttribute("username", username);
							request.setAttribute("message", "The username already exists£¡");
							request.getRequestDispatcher(sysdir+"/system/user.jsp").forward(request, response);
						}
						else{
							request.setAttribute("message", "System maintenance, please try again later!");
							request.getRequestDispatcher(sysdir+"/system/user.jsp").forward(request, response);
						}		
					
				}
			}
			else if(method.equals("delm")){//delete manager
				String username2 = (String)session.getAttribute("user");
				if(username2 == null){
					request.getRequestDispatcher("error.jsp").forward(request, response);
				}
				else{
					int id = Integer.parseInt(request.getParameter("id").trim());
					if(id == 1){
						request.setAttribute("message", "Cannot delete original account number£¡");
						request.getRequestDispatcher(sysdir+"/system/user.jsp").forward(request, response);
					}
					else{
						int flag = loginbean.delManager(id);
						if(flag == Constant.SUCCESS){
							request.setAttribute("message", "Delete successful£¡");
							request.getRequestDispatcher(sysdir+"/system/user.jsp").forward(request, response);
						}	
						else{
							request.setAttribute("message", "System maintenance, please try again later£¡");
							request.getRequestDispatcher(sysdir+"/system/user.jsp").forward(request, response);
						}	
					}
				}			
			}
			
			
			
			
			else if(method.equals("dellog")){//delete login note
				String username2 = (String)session.getAttribute("user");
				if(username2 == null){
					request.getRequestDispatcher("error.jsp").forward(request, response);
				}
				else{
					String check[] = request.getParameterValues("checkit");
					if(check == null){
						request.setAttribute("message", "Please select the record to delete£¡");
						request.getRequestDispatcher(sysdir+"/system/log.jsp").forward(request, response);
					}
					else{
						int id[]= new int[check.length];
						for(int i = 0;i<check.length;i++){
							int s = Integer.parseInt(check[i]);				
							id[i] = s;
						}
						int flag = loginbean.delLog(id);
						if(flag == Constant.SUCCESS){
							request.setAttribute("message", "Successful deletion of records£¡");
							request.getRequestDispatcher(sysdir+"/system/log.jsp").forward(request, response);
						}
						else{
							request.setAttribute("message", "System maintenance, please try again later£¡");
							request.getRequestDispatcher(sysdir+"/system/log.jsp").forward(request, response);
						}
					}
				}			
			}
			else{//Pass-in without parameters to error page
				request.getRequestDispatcher("error.jsp").forward(request, response);
			}
		}catch(Exception e){
			e.printStackTrace();
			request.getRequestDispatcher("error.jsp").forward(request, response);
		}
		
	}

	/**
	 * Initialization of the servlet. <br>
	 *
	 * @throws ServletException if an error occure
	 */
	public void init() throws ServletException {
		// Put your code here
	}

}
